//! Windows routing configuration for the TUN adapter.
//!
//! Strategy (mirrors what the macOS app's Network Extension does, translated
//! to Windows primitives):
//!
//! * Full-tunnel via the two half-default routes `0.0.0.0/1` + `128.0.0.0/1`
//!   through the tunnel gateway — more specific than the system default, so
//!   everything flows into the tunnel without touching the default route.
//! * IPv6 leak guard: `::/1` + `8000::/1` pinned to the TUN interface (the
//!   engine tunnels non-IPv4 packets and they die server-side — nothing
//!   escapes in the clear).
//! * Split tunnel: bypass CIDRs (explicit + builtin country lists) are routed
//!   through the *original* default gateway, captured before we install
//!   anything.
//! * DNS: besides the adapter's own resolver (set natively by the device
//!   layer), an NRPT "." rule routes *all* resolver traffic — v4 + v6, any
//!   interface, including Windows' multi-homed lookups — to the loopback DoH
//!   proxy.
//!
//! Writes go through `netsh` / `powershell` — built-in, transparent, and no
//! unsafe Win32 API surface. Reads use PowerShell JSON for structure.

use std::net::Ipv4Addr;
use std::process::Command;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Name of the Wintun adapter we create.
pub const ADAPTER_NAME: &str = "R-VPN";

/// Netmask for the server-assigned /24.
pub const TUNNEL_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

fn run(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to spawn {program}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !output.status.success() {
        let detail = if stderr.is_empty() { stdout.clone() } else { stderr };
        anyhow::bail!("{program} {:?} failed: {detail}", args);
    }
    Ok(stdout)
}

/// Run a command, log failures, but never fail the connect sequence.
fn run_best_effort(program: &str, args: &[&str]) {
    if let Err(e) = run(program, args) {
        tracing::warn!("{e} (continuing)");
    }
}

/// The pre-tunnel default route, captured before we install ours.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct DefaultRoute {
    #[serde(rename = "NextHop")]
    pub next_hop: String,
    #[serde(rename = "InterfaceAlias")]
    pub interface_alias: String,
}

impl DefaultRoute {
    /// True when the machine has a real default route we can bypass through.
    pub fn is_usable(&self) -> bool {
        !self.next_hop.is_empty() && self.next_hop != "0.0.0.0"
    }
}

/// Capture the current best default route via PowerShell (structured JSON).
pub fn capture_default_route() -> Result<DefaultRoute> {
    let out = run(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | \
             Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 \
             NextHop, InterfaceIndex, InterfaceAlias | ConvertTo-Json -Compress)",
        ],
    )?;
    if out.is_empty() {
        return Ok(DefaultRoute::default());
    }
    let route: DefaultRoute =
        serde_json::from_str(&out).context("failed to parse Get-NetRoute output")?;
    Ok(route)
}

/// Whether the NRPT "." rule was installed (reverted in `revert`).
#[derive(Debug, Default)]
pub struct RouteState {
    pub nrpt_added: bool,
}

/// Install the full-tunnel routes + leak guards + bypass routes.
///
/// `interface` is the adapter name for the netsh route commands.
pub fn install_routes(
    interface: &str,
    gateway: Ipv4Addr,
    original: &DefaultRoute,
    bypass_cidrs: &[String],
) -> Result<()> {
    // Full tunnel: the two half-defaults beat the system default on specificity.
    for half in ["0.0.0.0/1", "128.0.0.0/1"] {
        run(
            "netsh",
            &[
                "interface",
                "ipv4",
                "add",
                "route",
                &format!("prefix={half}"),
                &format!("interface={interface}"),
                &format!("nexthop={gateway}"),
                "metric=1",
                "store=active",
            ],
        )
        .with_context(|| format!("failed to install tunnel route {half}"))?;
    }

    // IPv6 leak guard: pin v6 halves to the TUN interface.
    for half in ["::/1", "8000::/1"] {
        run_best_effort(
            "netsh",
            &[
                "interface",
                "ipv6",
                "add",
                "route",
                &format!("prefix={half}"),
                &format!("interface={interface}"),
                "metric=1",
                "store=active",
            ],
        );
    }

    // Split tunnel: bypass CIDRs via the original gateway (captured earlier).
    if original.is_usable() {
        for cidr in bypass_cidrs {
            run_best_effort(
                "netsh",
                &[
                    "interface",
                    "ipv4",
                    "add",
                    "route",
                    &format!("prefix={cidr}"),
                    &format!("interface={}", original.interface_alias),
                    &format!("nexthop={}", original.next_hop),
                    "metric=1",
                    "store=active",
                ],
            );
        }
    } else if !bypass_cidrs.is_empty() {
        tracing::warn!("no original default route captured — bypass CIDRs skipped");
    }

    Ok(())
}

/// Remove the half-default tunnel routes (used when the server reassigns the
/// address and they must be reinstalled with a new gateway).
pub fn remove_tunnel_routes(interface: &str) {
    for half in ["0.0.0.0/1", "128.0.0.0/1"] {
        run_best_effort(
            "netsh",
            &[
                "interface",
                "ipv4",
                "delete",
                "route",
                &format!("prefix={half}"),
                &format!("interface={interface}"),
            ],
        );
    }
}

/// Add an NRPT "." rule so *all* resolver traffic (v4 + v6, any interface)
/// goes to the loopback DoH proxy. Best-effort — on SKUs without the
/// DnsClient module the adapter-scoped resolver still covers normal lookups.
pub fn add_nrpt_rule() -> RouteState {
    let nrpt = run(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "try { Add-DnsClientNrptRule -Namespace '.' -NameServer '127.0.0.1' -ErrorAction Stop | Out-Null; 'ok' } catch { 'skip' }",
        ],
    )
    .unwrap_or_default();
    let state = RouteState {
        nrpt_added: nrpt.trim() == "ok",
    };
    run_best_effort("ipconfig", &["/flushdns"]);
    state
}

/// Revert everything that does not die with the adapter itself.
pub fn revert(state: &RouteState) {
    if state.nrpt_added {
        run_best_effort(
            "powershell",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-DnsClientNrptRule -ErrorAction SilentlyContinue | \
                 Where-Object { $_.NameServer -eq '127.0.0.1' } | \
                 Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue",
            ],
        );
    }
    run_best_effort("ipconfig", &["/flushdns"]);
}

/// Derive the tunnel gateway when the server did not send one: the `.1`
/// host of the assigned /24, matching the CLI client's behaviour.
pub fn derive_gateway(ip: Ipv4Addr) -> Ipv4Addr {
    let octets = ip.octets();
    Ipv4Addr::new(octets[0], octets[1], octets[2], 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_derivation() {
        assert_eq!(
            derive_gateway("10.200.0.2".parse().unwrap()),
            "10.200.0.1".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn default_route_usability() {
        let r = DefaultRoute {
            next_hop: "192.168.1.1".into(),
            interface_alias: "Wi-Fi".into(),
        };
        assert!(r.is_usable());
        assert!(!DefaultRoute::default().is_usable());
        assert!(!DefaultRoute {
            next_hop: "0.0.0.0".into(),
            interface_alias: "Loopback".into(),
        }
        .is_usable());
    }
}
