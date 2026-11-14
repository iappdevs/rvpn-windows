//! The tunnel engine — the Windows equivalent of the macOS app's tunnel
//! controller. It owns, in one process:
//!
//! 1. the **rVPN engine** (`IosTunClient` from `rvpn-mobile`, used in-process
//!    exactly like the Swift host uses it over FFI): X3DH + Double Ratchet
//!    over WebSocket/TLS 1.3, reconnects, PSK resumption, multiplexed flows;
//! 2. the **loopback DoH DNS proxy** (`rvpn-mobile`'s DnsServer on
//!    127.0.0.1:53) with ad blocking and split-tunnel-aware resolution;
//! 3. the **Wintun adapter** and two pump threads moving raw IP packets
//!    between the ring buffer and the engine's packet channels;
//! 4. the **Windows plumbing**: virtual IP, half-default routes, IPv6 leak
//!    guard, bypass routes via the original gateway, NRPT DNS rule.
//!
//! The GUI talks to the engine through `EngineEvent`s (pushed over a
//! channel) and `EngineHandle::snapshot()` (polled each frame).
//!
//! Ownership/lifetimes: `ConnectFlow` acquires resources step by step and
//! **drops them in reverse order via `Drop` on any failure** — a failed
//! connect can never leak a runtime, a session, or a route. On success the
//! same bundle is moved into `Teardown` and unwound by `teardown_inner`.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use rvpn_mobile::ffi::TunConfig;
use rvpn_mobile::ios_tun::{IosTunClient, TunClientState};

use crate::profile::Profile;
use crate::tundevice::TunDevice;
use crate::winroute::{self, DefaultRoute, RouteState};

/// Events pushed to the UI.
#[derive(Debug, Clone)]
pub enum EngineEvent {
    /// Phase change of the engine lifecycle.
    Phase(EnginePhase),
    /// First-connection TOFU capture: pin the user should persist.
    TofuCaptured { slug: String, pin: String },
    /// Stored pin does not match the server.
    TofuMismatch { slug: String, expected: String, actual: String },
    /// Server-assigned address changed after a reconnect; routes updated.
    Readdressed { ip: String, gateway: String },
    /// Informational notice for the UI (non-fatal).
    Notice(String),
    /// Engine fully stopped (teardown finished).
    Stopped,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EnginePhase {
    Idle,
    Starting,
    /// Handshake / Windows plumbing in progress.
    Connecting { detail: String },
    Connected { ip: String, gateway: String, server: String },
    /// Engine reports failure; teardown follows.
    Failed { reason: String },
    Stopping,
}

/// Polled snapshot for the UI.
#[derive(Debug, Clone)]
pub struct EngineSnapshot {
    pub phase: EnginePhase,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub connected_for_secs: Option<u64>,
    pub server_pin: Option<String>,
}

/// Where events are pushed (single engine at a time, like the mobile apps).
static EVENT_SINK: OnceLock<Mutex<Option<std::sync::mpsc::Sender<EngineEvent>>>> = OnceLock::new();

fn send_event(ev: EngineEvent) {
    if let Some(sink) = EVENT_SINK.get() {
        if let Ok(guard) = sink.lock() {
            if let Some(tx) = guard.as_ref() {
                let _ = tx.send(ev);
            }
        }
    }
}

/// The engine's C-ABI state callback: logging only. Phase events for the UI
/// are derived by the engine thread, which has profile context.
unsafe extern "C" fn state_callback(state: i32, ip: *const std::os::raw::c_char, _msg: *const std::os::raw::c_char) {
    let ip_str = if ip.is_null() {
        String::new()
    } else {
        std::ffi::CStr::from_ptr(ip).to_string_lossy().into_owned()
    };
    tracing::info!(state, ip = %ip_str, "engine state changed");
}

/// Running engine handle. Cheap to clone; teardown is idempotent.
#[derive(Clone)]
pub struct EngineHandle {
    inner: Arc<EngineInner>,
}

pub struct EngineInner {
    phase: Mutex<EnginePhase>,
    stop_flag: Arc<AtomicBool>,
    rx_bytes: Arc<AtomicU64>,
    tx_bytes: Arc<AtomicU64>,
    connected_at: Mutex<Option<Instant>>,
    /// Everything acquired by a successful connect; unwound by teardown.
    teardown: Mutex<Option<Teardown>>,
    /// Pump threads (also set on partial failure so teardown can join them).
    pumps: Mutex<Vec<std::thread::JoinHandle<()>>>,
    /// Set once teardown has run (or a connect attempt definitively failed).
    torn_down: AtomicBool,
}

struct Teardown {
    runtime: Option<tokio::runtime::Runtime>,
    client: Option<Arc<IosTunClient>>,
    dns_task: Option<tokio::task::JoinHandle<()>>,
    watcher: Option<tokio::task::JoinHandle<()>>,
    device: Option<Arc<TunDevice>>,
    routes: RouteState,
}

impl Default for Teardown {
    fn default() -> Self {
        Self {
            runtime: None,
            client: None,
            dns_task: None,
            watcher: None,
            device: None,
            routes: RouteState::default(),
        }
    }
}

impl EngineHandle {
    /// Connect using `profile`. Runs the whole (blocking) startup sequence
    /// on the calling thread — the UI spawns this on a worker thread.
    pub fn connect(
        profile: &Profile,
        events: std::sync::mpsc::Sender<EngineEvent>,
    ) -> EngineHandle {
        let _ = EVENT_SINK.set(Mutex::new(Some(events)));

        let handle = EngineHandle {
            inner: Arc::new(EngineInner {
                phase: Mutex::new(EnginePhase::Starting),
                stop_flag: Arc::new(AtomicBool::new(false)),
                rx_bytes: Arc::new(AtomicU64::new(0)),
                tx_bytes: Arc::new(AtomicU64::new(0)),
                connected_at: Mutex::new(None),
                teardown: Mutex::new(None),
                pumps: Mutex::new(Vec::new()),
                torn_down: AtomicBool::new(false),
            }),
        };

        match handle.run_connect(profile) {
            Ok(()) => {}
            Err(e) => {
                tracing::error!(error = %format!("{e:#}"), "connect sequence failed");
                let reason = format!("{e:#}");
                handle.teardown();
                handle.set_phase(EnginePhase::Failed { reason });
            }
        }
        handle
    }

    fn set_phase(&self, phase: EnginePhase) {
        *self.inner.phase.lock().unwrap() = phase.clone();
        send_event(EngineEvent::Phase(phase));
    }

    pub fn snapshot(&self) -> EngineSnapshot {
        let phase = self.inner.phase.lock().unwrap().clone();
        let connected_for_secs = self
            .inner
            .connected_at
            .lock()
            .unwrap()
            .map(|t| t.elapsed().as_secs());
        let server_pin = self
            .inner
            .teardown
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|t| t.client.as_ref())
            .map(|c| c.server_identity_pin().to_string());
        EngineSnapshot {
            phase,
            rx_bytes: self.inner.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: self.inner.tx_bytes.load(Ordering::Relaxed),
            connected_for_secs,
            server_pin,
        }
    }

    pub fn is_active(&self) -> bool {
        !self.inner.torn_down.load(Ordering::SeqCst)
            && !matches!(*self.inner.phase.lock().unwrap(), EnginePhase::Idle)
    }

    /// Ask for teardown. Returns immediately; `Stopped` arrives via events.
    pub fn stop(&self) {
        self.set_phase(EnginePhase::Stopping);
        let inner = self.inner.clone();
        std::thread::Builder::new()
            .name("rvpn-stop".into())
            .spawn(move || {
                teardown_inner(&inner);
                *inner.phase.lock().unwrap() = EnginePhase::Idle;
                send_event(EngineEvent::Stopped);
            })
            .expect("failed to spawn stop thread");
    }

    fn teardown(&self) {
        teardown_inner(&self.inner);
        *self.inner.phase.lock().unwrap() = EnginePhase::Idle;
    }

    fn run_connect(&self, profile: &Profile) -> Result<()> {
        profile.validate().context("profile is not ready")?;

        // Resources acquired along the way; Drop unwinds on failure.
        let mut flow = Teardown::default();

        // ---- 1. Engine config ---------------------------------------------------
        let config = TunConfig {
            server_address: profile.server_address.clone(),
            identity_key_path: profile.identity_path().to_string_lossy().into_owned(),
            prekey_bundle_path: profile.prekey_path().to_string_lossy().into_owned(),
            dns_servers: profile.dns_servers.clone(),
            bypass_networks: profile.bypass_networks.clone(),
            mtu: profile.mtu,
            split_tunnel_enabled: profile.split_tunnel_enabled,
            builtin_bypass_countries: profile.builtin_bypass_countries.clone(),
            bypass_domains: profile.bypass_domains.clone(),
            tunnel_domains: profile.tunnel_domains.clone(),
            block_ads: profile.block_ads,
            dns_bind_addr: "127.0.0.1:53".into(),
            enable_dns_proxy: true,
            stealth_fingerprint: None,
            server_identity_pin: profile.server_identity_pin.clone(),
            country_ips_file: None,
            extra_servers: Vec::new(),
            routing: std::collections::HashMap::new(),
        };

        // ---- 2. Tokio runtime (dropped LAST — see teardown_inner) ---------------
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("rvpn-engine")
            .build()
            .context("failed to create the engine runtime")?;

        // ---- 3. Engine client — the TOFU check happens here ---------------------
        self.set_phase(EnginePhase::Connecting { detail: "handshaking".into() });
        let client = match IosTunClient::new(&config, runtime.handle().clone()) {
            Ok(c) => Arc::new(c),
            Err(e) => {
                if let Some(rvpn_core::Error::ServerIdentityMismatch { expected, actual }) =
                    e.downcast_ref::<rvpn_core::Error>()
                {
                    send_event(EngineEvent::TofuMismatch {
                        slug: profile.slug.clone(),
                        expected: expected.clone(),
                        actual: actual.clone(),
                    });
                }
                drop(runtime);
                return Err(e.context("failed to initialize the tunnel engine"));
            }
        };
        client.set_state_callback(Some(state_callback));

        // ---- 4. Loopback DoH DNS proxy ------------------------------------------
        let dns_task = {
            let c = client.clone();
            runtime.spawn(async move {
                if let Err(e) = rvpn_mobile::ios_tun_ffi::start_dns_proxy_for_direct_tun(&c).await
                {
                    tracing::error!(error = %e, "DNS proxy exited");
                }
            })
        };

        // ---- 5. Wintun adapter ----------------------------------------------------
        self.set_phase(EnginePhase::Connecting { detail: "creating adapter".into() });
        let device = Arc::new(TunDevice::create(profile.mtu)?);

        // ---- 6. Start the engine and wait for the virtual IP ----------------------
        self.set_phase(EnginePhase::Connecting { detail: "connecting".into() });
        client.set_reconnect_enabled(true);
        client.start();

        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match client.get_state() {
                TunClientState::Connected | TunClientState::IpAssigned => break,
                TunClientState::Error => anyhow::bail!("engine entered an error state"),
                _ => {}
            }
            if Instant::now() > deadline {
                anyhow::bail!("timed out waiting for the server to assign an address");
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        let ip: Ipv4Addr = client
            .get_tunnel_ip()
            .and_then(|s| s.parse().ok())
            .context("server did not assign a tunnel IP")?;
        let gateway: Ipv4Addr = client
            .get_gateway_ip()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| winroute::derive_gateway(ip));

        // ---- 7. Windows plumbing ---------------------------------------------------
        self.set_phase(EnginePhase::Connecting { detail: "configuring routes".into() });
        let original_route = winroute::capture_default_route()?;
        device
            .configure_address(ip, winroute::TUNNEL_NETMASK)
            .context("failed to configure the tunnel interface")?;

        let mut bypass_cidrs: Vec<String> = profile.bypass_networks.clone();
        if profile.split_tunnel_enabled {
            for country in &profile.builtin_bypass_countries {
                if let Some(cidrs) = rvpn_mobile::rvpn_split_tunnel::get_country_ips(country) {
                    bypass_cidrs.extend(cidrs.iter().map(|s| s.to_string()));
                } else {
                    tracing::warn!(country, "unknown bypass country code");
                }
            }
        }
        winroute::install_routes(winroute::ADAPTER_NAME, gateway, &original_route, &bypass_cidrs)
            .context("failed to install tunnel routes")?;

        // DNS strategy: the loopback DoH proxy needs UDP 127.0.0.1:53. Local
        // DNS tools (e.g. Shecan/nextdns) often hold that port — routing the
        // system resolver at 127.0.0.1 then leaks queries to that tool
        // instead of the tunnel, which breaks name resolution mid-session.
        // Detect it and fall back to the profile's resolvers (carried inside
        // the tunnel by the 0/1+128/1 routes) instead.
        let local_dns_port_free = std::net::UdpSocket::bind("127.0.0.1:53").is_ok();
        let routes;
        if local_dns_port_free {
            device
                .configure_dns(&[std::net::IpAddr::from(std::net::Ipv4Addr::LOCALHOST)])
                .context("failed to set the tunnel DNS resolver")?;
            routes = winroute::add_nrpt_rule();
        } else {
            let fallback: Vec<std::net::IpAddr> = profile
                .dns_servers
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect();
            let fallback = if fallback.is_empty() {
                vec![std::net::IpAddr::from(std::net::Ipv4Addr::new(1, 1, 1, 1))]
            } else {
                fallback
            };
            tracing::warn!(
                servers = ?fallback,
                "127.0.0.1:53 is taken by another DNS tool — using the profile resolvers via the tunnel"
            );
            device
                .configure_dns(&fallback)
                .context("failed to set the tunnel DNS resolver")?;
            routes = winroute::RouteState::default(); // no NRPT: 127.0.0.1 would point at the other tool
            send_event(EngineEvent::Notice(
                "Local DNS port 53 is used by another tool (e.g. Shecan) — \
                 resolving via 1.1.1.1 through the tunnel."
                    .into(),
            ));
        }

        // ---- 8. Pumps ----------------------------------------------------------------
        self.spawn_pumps(&client, &device);

        // ---- 9. Watcher: TOFU capture + re-address after reconnects -------------------
        let watcher = Self::spawn_watcher(
            &runtime,
            &client,
            &self.inner,
            profile.slug.clone(),
            profile.server_identity_pin.is_some(),
            ip,
        );

        // ---- 10. Ready -----------------------------------------------------------------
        *self.inner.connected_at.lock().unwrap() = Some(Instant::now());
        flow.runtime = Some(runtime);
        flow.client = Some(client);
        flow.dns_task = Some(dns_task);
        flow.watcher = Some(watcher);
        flow.device = Some(device);
        flow.routes = routes;
        *self.inner.teardown.lock().unwrap() = Some(flow);
        self.set_phase(EnginePhase::Connected {
            ip: ip.to_string(),
            gateway: gateway.to_string(),
            server: profile.server_address.clone(),
        });
        Ok(())
    }

    fn spawn_pumps(&self, client: &Arc<IosTunClient>, device: &Arc<TunDevice>) {
        // Uplink: OS ring → engine. `receive_blocking` parks the thread until
        // a packet arrives or the session shuts down — no polling, no wakeups.
        let stop = self.inner.stop_flag.clone();
        let tx_bytes = self.inner.tx_bytes.clone();
        let client_up = client.clone();
        let dev_up = device.clone();
        let up = std::thread::Builder::new()
            .name("rvpn-pump-up".into())
            .spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let Some(packet) = dev_up.receive_blocking() else {
                        break; // session shut down
                    };
                    tx_bytes.fetch_add(packet.len() as u64, Ordering::Relaxed);
                    if let Err(e) = client_up.try_send_packet(packet) {
                        tracing::debug!(error = %e, "uplink queue full — packet dropped");
                    }
                }
            })
            .expect("failed to spawn uplink pump");

        // Downlink: engine → OS ring. `wait_for_packet` parks on a condvar;
        // drain everything that arrived behind it. Each received item is a
        // BATCH of packets in [u16-LE length][raw IP packet] form (the same
        // format the Swift host consumes) — unbatch before writing to TUN.
        let stop = self.inner.stop_flag.clone();
        let rx_bytes = self.inner.rx_bytes.clone();
        let client_down = client.clone();
        let dev_down = device.clone();
        let down = std::thread::Builder::new()
            .name("rvpn-pump-down".into())
            .spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    if client_down.wait_for_packet(200) == 1 {
                        while let Some(batch) = client_down.recv_packet_from_server() {
                            for_each_packet(&batch, |packet| {
                                rx_bytes.fetch_add(packet.len() as u64, Ordering::Relaxed);
                                if let Err(e) = dev_down.send(packet) {
                                    tracing::debug!(error = %e, "downlink write failed");
                                }
                            });
                        }
                    }
                }
            })
            .expect("failed to spawn downlink pump");

        self.inner.pumps.lock().unwrap().extend([up, down]);
    }

    fn spawn_watcher(
        runtime: &tokio::runtime::Runtime,
        client: &Arc<IosTunClient>,
        inner: &Arc<EngineInner>,
        slug: String,
        had_pin: bool,
        initial_ip: Ipv4Addr,
    ) -> tokio::task::JoinHandle<()> {
        let client = client.clone();
        let inner = inner.clone();
        runtime.spawn(async move {
            let mut last_ip = initial_ip;
            let mut announced_capture = false;
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                if inner.stop_flag.load(Ordering::Relaxed) {
                    return;
                }
                if !announced_capture && client.get_state() == TunClientState::Connected {
                    announced_capture = true;
                    let pin = client.server_identity_pin().to_string();
                    if !had_pin && !pin.is_empty() {
                        send_event(EngineEvent::TofuCaptured { slug: slug.clone(), pin });
                    }
                }
                if let Some(new_ip) = client
                    .get_tunnel_ip()
                    .and_then(|s| s.parse::<Ipv4Addr>().ok())
                {
                    if new_ip != last_ip {
                        last_ip = new_ip;
                        let gw = client
                            .get_gateway_ip()
                            .and_then(|s| s.parse().ok())
                            .unwrap_or_else(|| winroute::derive_gateway(new_ip));
                        tracing::info!(ip = %new_ip, gateway = %gw, "server reassigned address — updating interface");
                        let dev = inner.teardown.lock().unwrap().as_ref().and_then(|t| t.device.clone());
                        if let Some(dev) = dev {
                            let _ = dev.configure_address(new_ip, winroute::TUNNEL_NETMASK);
                            winroute::remove_tunnel_routes(winroute::ADAPTER_NAME);
                            let _ = winroute::install_routes(
                                winroute::ADAPTER_NAME,
                                gw,
                                &DefaultRoute::default(),
                                &[],
                            );
                        }
                        send_event(EngineEvent::Readdressed {
                            ip: new_ip.to_string(),
                            gateway: gw.to_string(),
                        });
                    }
                }
            }
        })
    }
}

fn teardown_inner(inner: &EngineInner) {
    if inner.torn_down.swap(true, Ordering::SeqCst) {
        return;
    }
    inner.stop_flag.store(true, Ordering::SeqCst);

    let teardown = inner.teardown.lock().unwrap().take();
    let Some(mut t) = teardown else {
        // Early-failure path: only pumps may exist (plus whatever run_connect
        // still owns — its stack values unwind by dropping normally).
        join_pumps(inner);
        return;
    };

    tracing::info!("tearing the tunnel down");

    // Unblock the uplink pump's parked receive first, then join both pumps.
    if let Some(dev) = t.device.as_ref() {
        dev.stop();
    }
    join_pumps(inner);

    // Stop the engine (WebSocket + reconnect loops) and the background tasks.
    if let Some(client) = t.client.as_ref() {
        client.set_reconnect_enabled(false);
        client.stop();
    }
    if let Some(task) = t.dns_task.take() {
        task.abort();
    }
    if let Some(task) = t.watcher.take() {
        task.abort();
    }

    // Drop the device handle — when the last reference goes, the Wintun
    // adapter closes and interface-scoped routes/DNS die with it.
    t.device = None;
    winroute::revert(&t.routes);

    // The runtime must be dropped last, off any tokio worker thread
    // (Runtime::drop shuts the blocking pool down synchronously).
    t.runtime = None;

    tracing::info!("teardown complete");
}

fn join_pumps(inner: &EngineInner) {
    let pumps: Vec<_> = inner.pumps.lock().unwrap().drain(..).collect();
    for pump in pumps {
        let _ = pump.join();
    }
}

/// Iterate the `[u16-LE length][raw IP packet]` entries of a downlink batch.
/// Malformed tails are skipped defensively (never panic in the pump thread).
pub(crate) fn for_each_packet(batch: &[u8], mut f: impl FnMut(&[u8])) {
    let mut off = 0usize;
    while off + 2 <= batch.len() {
        let plen = u16::from_le_bytes([batch[off], batch[off + 1]]) as usize;
        off += 2;
        if off + plen > batch.len() {
            tracing::warn!("downlink batch truncated at {off} (need {plen})");
            return;
        }
        f(&batch[off..off + plen]);
        off += plen;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_is_cloneable_and_matchable() {
        let p = EnginePhase::Connected {
            ip: "10.0.0.2".into(),
            gateway: "10.0.0.1".into(),
            server: "wss://example.com".into(),
        };
        let EnginePhase::Connected { ip, .. } = p.clone() else {
            panic!("wrong variant");
        };
        assert_eq!(ip, "10.0.0.2");
    }

    #[test]
    fn batch_iteration_yields_all_packets() {
        // [len=2][de] [len=3][abc]
        let mut batch = Vec::new();
        batch.extend_from_slice(&2u16.to_le_bytes());
        batch.extend_from_slice(b"de");
        batch.extend_from_slice(&3u16.to_le_bytes());
        batch.extend_from_slice(b"abc");

        let mut out = Vec::new();
        for_each_packet(&batch, |p| out.push(p.to_vec()));
        assert_eq!(out, vec![b"de".to_vec(), b"abc".to_vec()]);
    }

    #[test]
    fn batch_iteration_skips_truncated_tail() {
        let mut batch = Vec::new();
        batch.extend_from_slice(&2u16.to_le_bytes());
        batch.extend_from_slice(b"de");
        batch.extend_from_slice(&10u16.to_le_bytes()); // claims 10, nothing left
        let mut out = Vec::new();
        for_each_packet(&batch, |p| out.push(p.to_vec()));
        assert_eq!(out, vec![b"de".to_vec()]);
    }
}
