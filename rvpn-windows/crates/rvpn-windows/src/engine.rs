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
use std::sync::{Arc, Mutex};
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
    TofuMismatch {
        slug: String,
        expected: String,
        actual: String,
    },
    /// Server-assigned address changed after a reconnect; routes updated.
    Readdressed { ip: String, gateway: String },
    /// Informational notice for the UI (non-fatal).
    Notice(String),
    /// Result of the pre-connect database update, retained in the status card.
    GeoDataStatus { description: String, warning: bool },
    /// Engine fully stopped (teardown finished).
    Stopped,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EnginePhase {
    Idle,
    Starting,
    /// Handshake / Windows plumbing in progress.
    Connecting {
        detail: String,
    },
    Connected {
        ip: String,
        gateway: String,
        server: String,
    },
    /// Engine reports failure; teardown follows.
    Failed {
        reason: String,
    },
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
static EVENT_SINK: Mutex<Option<std::sync::mpsc::Sender<EngineEvent>>> = Mutex::new(None);

fn send_event(ev: EngineEvent) {
    if let Ok(guard) = EVENT_SINK.lock() {
        if let Some(tx) = guard.as_ref() {
            let _ = tx.send(ev);
        }
    }
}

/// The engine's C-ABI state callback: logging only. Phase events for the UI
/// are derived by the engine thread, which has profile context.
unsafe extern "C" fn state_callback(
    state: i32,
    ip: *const std::os::raw::c_char,
    _msg: *const std::os::raw::c_char,
) {
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
    stop_requested: AtomicBool,
    teardown_done: (Mutex<bool>, std::sync::Condvar),
}

struct Teardown {
    runtime: Option<tokio::runtime::Runtime>,
    client: Option<Arc<IosTunClient>>,
    dns_task: Option<tokio::task::JoinHandle<()>>,
    watcher: Option<tokio::task::JoinHandle<()>>,
    device: Option<Arc<TunDevice>>,
    routes: RouteState,
    /// Proxy-mode state (mutually exclusive with the TUN fields).
    proxy: Option<ProxyTeardown>,
}

/// Running pieces of proxy mode to unwind on stop.
struct ProxyTeardown {
    mixed: crate::proxy::MixedProxy,
    socks: rvpn_mobile::socks5_server::Socks5ServerHandle,
    flow_task: tokio::task::AbortHandle,
    udp_task: tokio::task::AbortHandle,
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
            proxy: None,
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
        Self::connect_cancellable(profile, events, Arc::new(AtomicBool::new(false)))
    }

    pub fn connect_cancellable(
        profile: &Profile,
        events: std::sync::mpsc::Sender<EngineEvent>,
        cancel: Arc<AtomicBool>,
    ) -> EngineHandle {
        *EVENT_SINK.lock().unwrap() = Some(events);

        let handle = EngineHandle {
            inner: Arc::new(EngineInner {
                phase: Mutex::new(EnginePhase::Starting),
                stop_flag: cancel,
                rx_bytes: Arc::new(AtomicU64::new(0)),
                tx_bytes: Arc::new(AtomicU64::new(0)),
                connected_at: Mutex::new(None),
                teardown: Mutex::new(None),
                pumps: Mutex::new(Vec::new()),
                torn_down: AtomicBool::new(false),
                stop_requested: AtomicBool::new(false),
                teardown_done: (Mutex::new(false), std::sync::Condvar::new()),
            }),
        };

        let result = if handle.inner.stop_flag.load(Ordering::SeqCst) {
            Err(anyhow::anyhow!("Connection cancelled"))
        } else {
            match profile.mode {
                crate::profile::ConnMode::Tun => handle.run_connect(profile),
                crate::profile::ConnMode::Proxy => handle.run_connect_proxy(profile),
            }
        };
        match result {
            Ok(()) => {}
            Err(_) if handle.inner.stop_flag.load(Ordering::SeqCst) => {
                handle.teardown();
                handle.set_phase(EnginePhase::Idle);
                tracing::info!("connection cancelled");
            }
            Err(e) => {
                tracing::error!(error = %format!("{e:#}"), "connect sequence failed");
                let reason = format!("{e:#}");
                handle.teardown();
                handle.set_phase(EnginePhase::Failed { reason });
            }
        }
        handle
    }

    /// SOCKS5 proxy mode: a local 127.0.0.1 listener with split-tunnel rules —
    /// bypassed hosts (Iranian domains/IPs) go straight over the normal
    /// internet, everything else rides per-flow encrypted WebSockets to the
    /// server. No TUN adapter, no routes, no Administrator rights.
    fn run_connect_proxy(&self, profile: &Profile) -> Result<()> {
        use rvpn_mobile::flow_connector::FlowConnectorConfig;
        use rvpn_mobile::socks5_server::{
            DnsConfig, Socks5Server, Socks5ServerConfig, TunnelRequest,
        };

        profile.validate().context("profile is not ready")?;

        // TOFU: the pin is computed from the bundle, so we can enforce the
        // stored pin BEFORE any connection attempt.
        let bundle_text = std::fs::read_to_string(profile.prekey_path())
            .context("failed to read the prekey bundle")?;
        let actual_pin = crate::identity::validate_prekey_text(&bundle_text)?;
        if let Some(expected) = &profile.server_identity_pin {
            if expected != &actual_pin {
                send_event(EngineEvent::TofuMismatch {
                    slug: profile.slug.clone(),
                    expected: expected.clone(),
                    actual: actual_pin,
                });
                anyhow::bail!(
                    "server identity mismatch — pin stored in the profile differs from the bundle"
                );
            }
        }

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("rvpn-proxy")
            .build()
            .context("failed to create the proxy runtime")?;

        let identity =
            rvpn_core::crypto::IdentityKey::load(&profile.identity_path()).context("identity")?;
        let bundle: rvpn_core::crypto::X3DHPublicBundle =
            serde_json::from_str(&bundle_text).context("invalid prekey bundle")?;

        // Route once in the Windows mixed inbound. The internal SOCKS engine
        // only carries Proxy outbounds; it must not re-apply bypass rules.
        let listen: std::net::SocketAddr = format!("127.0.0.1:{}", profile.proxy_port)
            .parse()
            .context("invalid proxy port")?;

        let dns = DnsConfig {
            tunnel_dns: profile.dns_servers.clone(),
            bypass_dns: profile.bypass_dns_servers.clone(),
        };

        // Parse the server endpoint into (host, port, base path).
        let endpoint = profile.socks_endpoint();
        let (host_port, path) = endpoint
            .strip_prefix("wss://")
            .or_else(|| endpoint.strip_prefix("ws://"))
            .unwrap_or(&endpoint)
            .split_once('/')
            .map(|(hp, p)| (hp.to_string(), format!("/{p}")))
            .unwrap_or((endpoint.clone(), "/api/v1/ws".to_string()));
        let (server_host, server_port) = host_port
            .rsplit_once(':')
            .map(|(h, p)| (h.to_string(), p.parse::<u16>().unwrap_or(443)))
            .unwrap_or((host_port.clone(), 443));

        let socks_config = Socks5ServerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            split_tunnel: None,
            dns_config: Some(dns),
            direct_bypass: true,
        };

        self.set_phase(EnginePhase::Connecting {
            detail: "starting proxy".into(),
        });
        let server = runtime
            .block_on(Socks5Server::new(socks_config))
            .context("failed to initialize the SOCKS5 frontend")?;

        let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel::<TunnelRequest>(256);
        let (_udp_tx, mut udp_rx) =
            tokio::sync::mpsc::channel::<rvpn_mobile::socks5_server::UdpAssociationRequest>(16);

        let handle = runtime
            .block_on(server.run_with_shutdown(tun_tx, _udp_tx))
            .context("failed to bind the SOCKS5 listener")?;
        let backend_addr = handle.local_addr;

        // TCP flows → per-flow encrypted WebSocket to the server.
        let flow_config = FlowConnectorConfig {
            server_host,
            server_port,
            server_path: path,
            tls_fingerprint: rvpn_tls::TlsFingerprint::Chrome,
            identity_key: Arc::new(identity),
            server_bundle: bundle,
            resumption: None,
        };

        let _stop = self.inner.stop_flag.clone();
        let rx_bytes = self.inner.rx_bytes.clone();
        let tx_bytes = self.inner.tx_bytes.clone();
        let flow_task = {
            let flow_config = flow_config.clone();
            runtime.spawn(async move {
                while let Some(req) = tun_rx.recv().await {
                    let cfg = flow_config.clone();
                    let rx = rx_bytes.clone();
                    let tx = tx_bytes.clone();
                    tokio::spawn(async move {
                        let mut socket = req.socket;
                        let addr = req.target_address.clone();
                        // strip a possible trailing port split for host parse
                        let (host, port) = match addr.rsplit_once(':') {
                            Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(80)),
                            None => (addr.clone(), 80),
                        };
                        let host = host.trim_matches(['[', ']']);
                        let host = host.to_string();
                        let counters = make_delta_counter(rx, tx);
                        // Transient link resets (RST bursts on the Iran↔server
                        // path) kill brand-new handshakes; a short retry turns
                        // most of them into a 400 ms hiccup instead of a
                        // browser error page. Only retried while nothing has
                        // been relayed yet — a mid-stream failure is real.
                        let mut result = relay_flow_with_retry(&cfg, &host, port, &mut socket, &counters).await;
                        if let Err(e) = &result {
                            tracing::debug!(error = %format!("{e:#}"), "flow ended with error");
                        }
                        let _ = req.completion_sender.send(result.map(|_| ())).await;
                    });
                }
            })
        };

        // UDP ASSOCIATE is not carried in proxy mode (browsers are fine with
        // TCP-only SOCKS5 + remote DNS); answer immediately so clients retry.
        let udp_task = runtime.spawn(async move {
            while let Some(req) = udp_rx.recv().await {
                let _ = req
                    .completion_sender
                    .send(Err(anyhow::anyhow!(
                        "UDP associate not supported in proxy mode"
                    )))
                    .await;
            }
        });

        // Readiness probe: a SOCKS5 CONNECT through our own listener to a
        // harmless target proves TLS + X3DH + relay end-to-end before we
        // report Connected.
        self.set_phase(EnginePhase::Connecting {
            detail: "handshaking".into(),
        });
        let probe = runtime.block_on(async {
          tokio::select! {
           _ = wait_for_cancel(self.inner.stop_flag.clone()) => false,
           result = async {
          tokio::time::timeout(std::time::Duration::from_secs(20), async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let Ok(mut s) = tokio::net::TcpStream::connect(backend_addr).await else {
                return false;
            };
            if s.write_all(&[0x05, 0x01, 0x00]).await.is_err() {
                return false;
            }
            let mut b = [0u8; 2];
            if s.read_exact(&mut b).await.is_err() || b[0] != 0x05 {
                return false;
            }
            // CONNECT example.com:80 (domain-name address type)
            let host = b"example.com";
            let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
            req.extend_from_slice(host);
            req.extend_from_slice(&80u16.to_be_bytes());
            if s.write_all(&req).await.is_err() {
                return false;
            }
            let mut resp = [0u8; 10];
            if s.read_exact(&mut resp).await.is_err() || resp[1] != 0x00 { return false; }
            // The engine acknowledges CONNECT before the remote handshake.
            // Verify actual bytes, not just that local acknowledgement.
            if s.write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n").await.is_err() { return false; }
            let mut status = [0; 5];
            s.read_exact(&mut status).await.is_ok() && &status == b"HTTP/"
          }).await.unwrap_or(false)
           } => result,
          }
        });
        if !probe {
            anyhow::bail!("proxy self-test failed — could not open a test flow through the server");
        }

        let report = runtime
            .block_on(async {
                tokio::select! {
                    _ = wait_for_cancel(self.inner.stop_flag.clone()) => None,
                    report = crate::geodata::refresh_before_proxy(backend_addr, |detail| {
                        self.set_phase(EnginePhase::Connecting { detail });
                    }) => Some(report),
                }
            })
            .context("Connection cancelled")?;
        send_event(EngineEvent::GeoDataStatus {
            description: report.description(),
            warning: report.warning.is_some(),
        });
        let router = crate::routing::Router::for_profile(profile)
            .context("invalid proxy routing rules")?
            .with_tunnel_dns(backend_addr, &profile.dns_servers)?;
        let mixed = runtime.block_on(crate::proxy::MixedProxy::start(
            listen,
            backend_addr,
            router,
        ))?;
        let local_addr = mixed.local_addr;

        // Persist the running pieces for teardown.
        *self.inner.connected_at.lock().unwrap() = Some(Instant::now());
        let mut teardown = Teardown::default();
        teardown.runtime = Some(runtime);
        teardown.proxy = Some(ProxyTeardown {
            mixed,
            socks: handle,
            flow_task: flow_task.abort_handle(),
            udp_task: udp_task.abort_handle(),
        });
        *self.inner.teardown.lock().unwrap() = Some(teardown);
        anyhow::ensure!(
            !self.inner.stop_flag.load(Ordering::SeqCst),
            "Connection cancelled"
        );

        if profile.server_identity_pin.is_none() {
            send_event(EngineEvent::TofuCaptured {
                slug: profile.slug.clone(),
                pin: actual_pin,
            });
        }

        // Do not report Connected until Windows points at the live listener.
        crate::sysproxy::set_system_proxy("127.0.0.1", profile.proxy_port)
            .context("Cannot enable Windows system proxy")?;

        self.set_phase(EnginePhase::Connected {
            ip: format!("http/socks5://{local_addr}"),
            gateway: "bypass rules active".into(),
            server: profile.server_address.clone(),
        });
        send_event(EngineEvent::Notice(format!(
            "HTTP/SOCKS proxy on {local_addr} — ordered routing rules active; reconnect after editing rules"
        )));
        Ok(())
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
        if self.inner.torn_down.load(Ordering::SeqCst)
            || self.inner.stop_requested.swap(true, Ordering::SeqCst)
        {
            return;
        }
        self.inner.stop_flag.store(true, Ordering::SeqCst);
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

    pub fn is_stopped(&self) -> bool {
        *self.inner.teardown_done.0.lock().unwrap()
    }

    /// Exit fallback: never let the process disappear while cleanup is running.
    pub fn stop_and_wait(&self) {
        self.teardown();
        let (done, wake) = &self.inner.teardown_done;
        let mut done = done.lock().unwrap();
        while !*done {
            done = wake.wait(done).unwrap();
        }
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
        self.set_phase(EnginePhase::Connecting {
            detail: "handshaking".into(),
        });
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
                if let Err(e) = rvpn_mobile::ios_tun_ffi::start_dns_proxy_for_direct_tun(&c).await {
                    tracing::error!(error = %e, "DNS proxy exited");
                }
            })
        };

        // ---- 5. Wintun adapter ----------------------------------------------------
        self.set_phase(EnginePhase::Connecting {
            detail: "creating adapter".into(),
        });
        let device = Arc::new(TunDevice::create(profile.mtu)?);

        // ---- 6. Start the engine and wait for the virtual IP ----------------------
        self.set_phase(EnginePhase::Connecting {
            detail: "connecting".into(),
        });
        client.set_reconnect_enabled(true);
        client.start();

        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if self.inner.stop_flag.load(Ordering::SeqCst) {
                client.set_reconnect_enabled(false);
                client.stop();
                anyhow::bail!("Connection cancelled");
            }
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
        self.set_phase(EnginePhase::Connecting {
            detail: "configuring routes".into(),
        });
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
        winroute::install_routes(
            winroute::ADAPTER_NAME,
            gateway,
            &original_route,
            &bypass_cidrs,
        )
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
        anyhow::ensure!(
            !self.inner.stop_flag.load(Ordering::SeqCst),
            "Connection cancelled"
        );
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

async fn wait_for_cancel(cancel: Arc<AtomicBool>) {
    while !cancel.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn teardown_inner(inner: &EngineInner) {
    if inner.torn_down.swap(true, Ordering::SeqCst) {
        return;
    }
    inner.stop_flag.store(true, Ordering::SeqCst);
    struct Complete<'a>(&'a EngineInner);
    impl Drop for Complete<'_> {
        fn drop(&mut self) {
            *self.0.teardown_done.0.lock().unwrap() = true;
            self.0.teardown_done.1.notify_all();
        }
    }
    let _complete = Complete(inner);

    let teardown = inner.teardown.lock().unwrap().take();
    let Some(mut t) = teardown else {
        // Early-failure path: only pumps may exist (plus whatever run_connect
        // still owns — its stack values unwind by dropping normally).
        join_pumps(inner);
        return;
    };

    tracing::info!("tearing the tunnel down");

    // Proxy mode: stop the SOCKS5 listener and the flow pump, restore the
    // system proxy, then the runtime drops below.
    if let Some(proxy) = t.proxy.take() {
        // Restore first, while the listener is still alive and before any
        // potentially slow task/runtime shutdown.
        crate::sysproxy::restore_system_proxy();
        drop(proxy.mixed);
        if let Some(rt) = t.runtime.as_ref() {
            rt.block_on(proxy.socks.stop());
        }
        proxy.flow_task.abort();
        proxy.udp_task.abort();
        t.runtime = None;
        tracing::info!("proxy mode teardown complete");
        return;
    }

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

/// Build the per-flow byte counter that converts `relay_flow`'s CUMULATIVE
/// per-flow up/down reports into deltas and adds them into the SESSION
/// totals — every request contributes; no flow ever overwrites the totals.
pub(crate) fn make_delta_counter(
    rx: Arc<AtomicU64>,
    tx: Arc<AtomicU64>,
) -> impl Fn(u64, u64) + Send + Sync + 'static {
    let last_up = Arc::new(AtomicU64::new(0));
    let last_down = Arc::new(AtomicU64::new(0));
    move |up: u64, down: u64| {
        let prev_up = last_up.swap(up, Ordering::Relaxed);
        let prev_down = last_down.swap(down, Ordering::Relaxed);
        tx.fetch_add(up.saturating_sub(prev_up), Ordering::Relaxed);
        rx.fetch_add(down.saturating_sub(prev_down), Ordering::Relaxed);
    }
}

/// `relay_flow` with up to two extra attempts while NOTHING has been
/// relayed yet (fresh handshakes killed by transient link resets — common
/// RST bursts on long-haul paths). Once any byte has flowed, a failure is
/// reported as-is: retrying a mid-stream break would corrupt the flow.
async fn relay_flow_with_retry<S>(
    cfg: &rvpn_mobile::flow_connector::FlowConnectorConfig,
    host: &str,
    port: u16,
    socket: &mut S,
    counters: &(dyn Fn(u64, u64) + Send + Sync),
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut attempt: u32 = 0;
    loop {
        let relayed_any = Arc::new(AtomicBool::new(false));
        let flagged = {
            let relayed_any = relayed_any.clone();
            move |up: u64, down: u64| {
                if up > 0 || down > 0 {
                    relayed_any.store(true, Ordering::Relaxed);
                }
                counters(up, down);
            }
        };
        match rvpn_mobile::flow_connector::relay_flow(cfg, host, port, socket, &flagged).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                if relayed_any.load(Ordering::Relaxed) || attempt >= 2 {
                    return Err(e);
                }
                attempt += 1;
                tracing::debug!(attempt, error = %format!("{e:#}"), "transient flow failure — retrying");
                tokio::time::sleep(Duration::from_millis(350)).await;
            }
        }
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
    fn session_counters_accumulate_across_flows() {
        // Three independent flows (each reporting its own cumulative totals,
        // as relay_flow does) must SUM into the session counters — the
        // second flow starting from zero again must not reset them.
        let rx = Arc::new(AtomicU64::new(0));
        let tx = Arc::new(AtomicU64::new(0));

        let flow1 = make_delta_counter(rx.clone(), tx.clone());
        flow1(100, 500);
        flow1(150, 900); // flow1 totals: up 150, down 900

        let after_flow1 = (tx.load(Ordering::Relaxed), rx.load(Ordering::Relaxed));
        assert_eq!(after_flow1, (150, 900));

        let flow2 = make_delta_counter(rx.clone(), tx.clone());
        flow2(50, 2000); // a NEW flow restarts from its own zero — must ADD
        let after_flow2 = (tx.load(Ordering::Relaxed), rx.load(Ordering::Relaxed));
        assert_eq!(after_flow2, (200, 2900));

        let flow3 = make_delta_counter(rx.clone(), tx.clone());
        flow3(10, 10);
        assert_eq!(
            (tx.load(Ordering::Relaxed), rx.load(Ordering::Relaxed)),
            (210, 2910)
        );
    }

    #[test]
    fn cancelled_startup_never_reports_a_connection_failure() {
        let (tx, _rx) = std::sync::mpsc::channel();
        let profile = Profile::new("cancelled-isolated-test");
        let handle =
            EngineHandle::connect_cancellable(&profile, tx, Arc::new(AtomicBool::new(true)));
        assert_eq!(handle.snapshot().phase, EnginePhase::Idle);
        assert!(handle.is_stopped());
    }

    #[test]
    fn shutdown_waits_for_cleanup_instead_of_only_the_stop_flag() {
        let handle = EngineHandle {
            inner: Arc::new(EngineInner {
                phase: Mutex::new(EnginePhase::Connected {
                    ip: "test".into(),
                    gateway: "test".into(),
                    server: "test".into(),
                }),
                stop_flag: Arc::new(AtomicBool::new(false)),
                rx_bytes: Arc::new(AtomicU64::new(0)),
                tx_bytes: Arc::new(AtomicU64::new(0)),
                connected_at: Mutex::new(None),
                teardown: Mutex::new(None),
                pumps: Mutex::new(vec![]),
                torn_down: AtomicBool::new(false),
                stop_requested: AtomicBool::new(false),
                teardown_done: (Mutex::new(false), std::sync::Condvar::new()),
            }),
        };
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let pump_barrier = barrier.clone();
        handle
            .inner
            .pumps
            .lock()
            .unwrap()
            .push(std::thread::spawn(move || {
                pump_barrier.wait();
            }));
        handle.stop();
        handle.stop();
        while !handle.inner.torn_down.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        assert!(
            !handle.is_stopped(),
            "teardown has started but the pump is still running"
        );
        let waiter = handle.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            waiter.stop_and_wait();
            tx.send(()).unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_millis(30)).is_err());
        barrier.wait();
        rx.recv_timeout(Duration::from_secs(3)).unwrap();
        worker.join().unwrap();
        assert!(handle.is_stopped());
    }

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
