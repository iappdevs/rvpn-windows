//! Wintun adapter ownership — the Windows equivalent of the macOS app's
//! `NWPacketTunnelProvider` packet interface.
//!
//! The `wintun` crate binds the official `wintun.dll` (shipped next to the
//! executable). `Adapter` exposes native IP-address/netmask/MTU/DNS setters
//! (IP Helper API under the hood), and `Session` is the ring-buffer packet
//! interface: `receive_blocking()` yields packets the OS routed into the
//! tunnel and unblocks with an error on shutdown; `allocate_send_packet` +
//! `send_packet` inject packets back.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use wintun::{Adapter, Session, Wintun};

/// Stable GUID for our adapter slot (u128 form of
/// {8D9B1C2A-4F3E-4C7B-9A6D-0E2F5B7C8A11}).
const ADAPTER_GUID: u128 = 0x8d9b1c2a_4f3e_4c7b_9a6d_0e2f5b7c8a11;

/// Where `wintun.dll` is expected: next to the executable.
pub fn wintun_dll_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dll = exe.parent()?.join("wintun.dll");
    dll.is_file().then_some(dll)
}

fn load_library() -> Result<Wintun> {
    // SAFETY: we only load the official wintun.dll we ship next to the exe
    // (or the system-searched one); no attacker-controlled search path is
    // used when the local file exists.
    unsafe {
        if let Some(path) = wintun_dll_path() {
            if let Ok(lib) = wintun::load_from_path(&path) {
                return Ok(lib);
            }
        }
        wintun::load().context("wintun.dll not found — ship it next to rvpn-windows.exe")
    }
}

/// A created Wintun adapter with an active packet session. Clonable handle
/// shared by the engine and both pump threads (`Session` is `Send + Sync`).
#[derive(Clone)]
pub struct TunDevice {
    adapter: Arc<Adapter>,
    session: Arc<Session>,
}

impl TunDevice {
    /// Create (or reuse) the `R-VPN` adapter and start its ring session.
    ///
    /// An adapter left over from a previous crashed run is deleted first so
    /// stale routing state never lingers.
    pub fn create(mtu: u16) -> Result<Self> {
        let lib = load_library()?;

        // Clean up a stale adapter from an unclean shutdown.
        if let Ok(old) = Adapter::open(&lib, super::winroute::ADAPTER_NAME) {
            tracing::info!("removing stale {} adapter", super::winroute::ADAPTER_NAME);
            if let Ok(s) = old.start_session(wintun::MIN_RING_CAPACITY) {
                let _ = s.shutdown();
            }
            if let Ok(owned) = Arc::try_unwrap(old) {
                let _ = owned.delete();
            }
        }

        let adapter = Adapter::create(
            &lib,
            super::winroute::ADAPTER_NAME,
            "R-VPN Tunnel (Wintun)",
            Some(ADAPTER_GUID),
        )
        .context("failed to create the Wintun adapter (Administrator rights required)")?;

        adapter
            .set_mtu(mtu as usize)
            .context("failed to set the adapter MTU")?;

        let session = Arc::new(
            adapter
                .start_session(0x4_0000) // 256 KiB ring
                .context("failed to start the Wintun session")?,
        );

        tracing::info!(adapter = super::winroute::ADAPTER_NAME, mtu, "Wintun adapter created");
        Ok(Self { adapter, session })
    }

    /// Native IP configuration on the adapter (IP Helper API — atomic, no shell).
    pub fn configure_address(&self, ip: Ipv4Addr, netmask: Ipv4Addr) -> Result<()> {
        self.adapter
            .set_address(ip)
            .context("failed to assign the tunnel IP")?;
        self.adapter
            .set_netmask(netmask)
            .context("failed to assign the tunnel netmask")?;
        Ok(())
    }

    /// Point the adapter's resolver at the given servers (primary order kept).
    pub fn configure_dns(&self, resolvers: &[std::net::IpAddr]) -> Result<()> {
        self.adapter
            .set_dns_servers(resolvers)
            .context("failed to set the tunnel DNS resolver")
    }

    /// Wait for the next packet the OS routed into the tunnel.
    /// Blocks until a packet arrives or the session shuts down (`None`).
    pub fn receive_blocking(&self) -> Option<Vec<u8>> {
        match self.session.receive_blocking() {
            Ok(packet) => Some(packet.bytes().to_vec()),
            Err(_) => None,
        }
    }

    /// Inject a packet towards the OS.
    pub fn send(&self, packet: &[u8]) -> Result<()> {
        let mut slot = self
            .session
            .allocate_send_packet(packet.len() as u16)
            .map_err(|e| anyhow::anyhow!("wintun allocate failed: {e}"))?;
        slot.bytes_mut().copy_from_slice(packet);
        self.session.send_packet(slot);
        Ok(())
    }

    /// Unblock the pumps. The adapter itself is deleted when the last
    /// `TunDevice` clone drops (interface-scoped routes and DNS settings
    /// die with the adapter).
    pub fn stop(&self) {
        let _ = self.session.shutdown();
    }
}
