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
//! Split-tunnel bypass routes go in through the IP Helper API in-process
//! (a GeoIP country is thousands of CIDRs); the handful of tunnel routes go
//! through `netsh` / `powershell`. Reads use PowerShell JSON for structure.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::process::Command;

use anyhow::{Context, Result};
use serde::Deserialize;
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex, CreateIpForwardEntry2,
    DeleteIpForwardEntry2, FreeMibTable, GetIpForwardTable2, InitializeIpForwardEntry,
    IP_ADDRESS_PREFIX, MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, IN_ADDR, IN_ADDR_0, MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_INET,
};

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

/// Remove every leftover NRPT rule this app may have created — the catch-all
/// `.` rules pointing at the loopback resolver. NOTE the property is the
/// PLURAL `NameServers` (filtering on `NameServer` silently matched nothing,
/// which is exactly how rules leaked and held the system resolver hostage
/// after disconnect).
fn sweep_nrpt_rules() {
    run_best_effort(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-DnsClientNrptRule -ErrorAction SilentlyContinue | \
             Where-Object { ($_.Namespace -contains '.') -and \
                            ($_.NameServers -contains '127.0.0.1' -or -not $_.NameServers) } | \
             Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue",
        ],
    );
}

/// Startup self-healing: rules can survive a crash or a forced process kill.
pub fn sweep_stale_state() {
    recover_route_journal();
    sweep_nrpt_rules();
    run_best_effort("ipconfig", &["/flushdns"]);
}

/// Revert everything that does not die with the adapter itself. The sweep is
/// unconditional — belt and braces over the recorded `nrpt_added` flag.
pub fn revert(_state: &RouteState) {
    sweep_nrpt_rules();
    run_best_effort("ipconfig", &["/flushdns"]);
}

/// Derive the tunnel gateway when the server did not send one: the `.1`
/// host of the assigned /24, matching the CLI client's behaviour.
pub fn derive_gateway(ip: Ipv4Addr) -> Ipv4Addr {
    let octets = ip.octets();
    Ipv4Addr::new(octets[0], octets[1], octets[2], 1)
}


// ============================================================================
// In-process bulk bypass routes (Win32 IP Helper API)
// ============================================================================

type ForwardRow = windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_ROW2;

/// Bypass routes this app installed on a physical interface.
///
/// Teardown removes exactly `cidrs`; a route that already existed when we
/// connected is not ours and stays. A copy sits in the journal
/// ([`journal_path`]) from install until removal, so a killed or crashed
/// process cannot strand thousands of routes on the NIC until the next boot.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct BypassBatch {
    pub interface_alias: String,
    pub next_hop: String,
    pub cidrs: Vec<String>,
    /// Routes of the request that already existed (someone else's).
    pub preexisting: usize,
}

/// Journal of the pending bypass batch: `<app data>/pending-routes.json`.
pub fn journal_path() -> std::path::PathBuf {
    crate::paths::app_data_dir().join("pending-routes.json")
}

/// "a.b.c.d/len" -> (address, prefix length)
fn parse_cidr(cidr: &str) -> Option<(Ipv4Addr, u8)> {
    let (ip, len) = cidr.split_once('/')?;
    Some((ip.parse().ok()?, len.parse().ok()?))
}

/// `IN_ADDR.S_addr` holds the address bytes in network order, so the raw
/// integer is NOT the address: always cross this boundary with these two.
fn addr_u32(ip: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(ip.octets())
}

/// Inverse of [`addr_u32`].
fn addr_from(raw: u32) -> Ipv4Addr {
    Ipv4Addr::from(raw.to_ne_bytes())
}

fn v4_sockaddr(ip: Ipv4Addr) -> SOCKADDR_INET {
    SOCKADDR_INET {
        Ipv4: SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 { S_addr: addr_u32(ip) },
            },
            sin_zero: [0; 8],
        },
    }
}

/// A route row for `prefix/len` via `next_hop` on `ifindex`.
fn forward_row(ifindex: u32, prefix: Ipv4Addr, len: u8, next_hop: Ipv4Addr) -> ForwardRow {
    let mut row: ForwardRow = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceIndex = ifindex;
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: v4_sockaddr(prefix),
        PrefixLength: len,
    };
    row.NextHop = v4_sockaddr(next_hop);
    row.Metric = 1;
    // Administratively configured, like `netsh`/`route add`. Recovery only
    // deletes NETMGMT routes that are also listed in our journal.
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row
}

fn interface_index(alias: &str) -> Result<u32> {
    let wide: Vec<u16> = alias.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `wide` is NUL-terminated and both out-pointers are valid.
    let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
    let rc = unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) };
    if rc != NO_ERROR {
        anyhow::bail!("network interface {alias:?} was not found (error {rc})");
    }
    let mut index = 0u32;
    let rc = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
    if rc != NO_ERROR {
        anyhow::bail!("network interface {alias:?} has no index (error {rc})");
    }
    Ok(index)
}

/// Add bypass routes through `interface_alias` in-process; returns the batch
/// this call created.
///
/// `netsh` costs a process spawn (~110 ms measured) per route, so a
/// `geoip:ir` rule (2.7k CIDRs) would hold the connect for ~5 minutes.
/// `CreateIpForwardEntry2` needs no child process.
pub fn add_bypass_routes_batch(
    interface_alias: &str,
    next_hop: Ipv4Addr,
    cidrs: &[String],
) -> Result<BypassBatch> {
    let index = interface_index(interface_alias)?;
    let mut batch = BypassBatch {
        interface_alias: interface_alias.to_string(),
        next_hop: next_hop.to_string(),
        cidrs: Vec::with_capacity(cidrs.len()),
        preexisting: 0,
    };
    let mut failed = 0usize;
    for cidr in cidrs {
        let Some((prefix, len)) = parse_cidr(cidr) else {
            tracing::warn!(cidr, "skipping unparsable bypass CIDR");
            continue;
        };
        // SAFETY: the row is fully initialised.
        let rc = unsafe { CreateIpForwardEntry2(&forward_row(index, prefix, len, next_hop)) };
        match rc {
            NO_ERROR => batch.cidrs.push(cidr.clone()),
            // Someone else's route for the same prefix: leave it alone.
            ERROR_OBJECT_ALREADY_EXISTS => batch.preexisting += 1,
            code => {
                failed += 1;
                if failed <= 5 {
                    tracing::warn!(cidr, code, "CreateIpForwardEntry2 failed");
                }
            }
        }
    }
    tracing::info!(
        created = batch.cidrs.len(),
        preexisting = batch.preexisting,
        failed,
        "bypass routes installed"
    );
    if failed > 0 && batch.cidrs.is_empty() {
        anyhow::bail!("none of the {} bypass routes could be installed", cidrs.len());
    }
    Ok(batch)
}

/// One row of the system's IPv4 route table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LiveRoute {
    dest: Ipv4Addr,
    len: u8,
    hop: Ipv4Addr,
    ifindex: u32,
    protocol: i32,
    /// Seconds since the route was created, as the system reports it.
    age: u32,
}

/// The system's IPv4 route table.
fn live_v4_routes() -> Result<Vec<LiveRoute>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: valid out-pointer; the table is released before returning.
    let rc = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
    if rc != NO_ERROR {
        anyhow::bail!("GetIpForwardTable2 failed (error {rc})");
    }
    let mut routes = Vec::new();
    // SAFETY: `table` holds `NumEntries` valid rows; reading the Ipv4 arm is
    // valid because AF_INET was requested.
    unsafe {
        let rows: *const ForwardRow = (*table).Table.as_ptr();
        for i in 0..(*table).NumEntries as usize {
            let row = &*rows.add(i);
            routes.push(LiveRoute {
                dest: addr_from(row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr),
                len: row.DestinationPrefix.PrefixLength,
                hop: addr_from(row.NextHop.Ipv4.sin_addr.S_un.S_addr),
                ifindex: row.InterfaceIndex,
                protocol: row.Protocol,
                age: row.Age,
            });
        }
        FreeMibTable(table.cast());
    }
    Ok(routes)
}

/// The prefix set of `batch` as `(address, prefix length)`.
fn wanted_prefixes(batch: &BypassBatch) -> HashSet<(Ipv4Addr, u8)> {
    batch.cidrs.iter().filter_map(|c| parse_cidr(c)).collect()
}

/// Live IPv4 routes of `batch`: `(destination, prefix length, ifindex)`.
/// Empty when the batch has no routes or the table cannot be read.
fn matching_routes(batch: &BypassBatch) -> Vec<(Ipv4Addr, u8, u32)> {
    let Some(next_hop) = batch.next_hop.parse::<Ipv4Addr>().ok() else {
        return Vec::new();
    };
    let wanted = wanted_prefixes(batch);
    if wanted.is_empty() {
        return Vec::new();
    }
    // The NIC may have been renamed since install; prefix + next hop still
    // identify our routes well enough then.
    let on_interface = interface_index(&batch.interface_alias).ok();

    let Ok(routes) = live_v4_routes() else {
        tracing::warn!("could not read the system route table");
        return Vec::new();
    };
    routes
        .iter()
        .filter(|r| {
            r.protocol == MIB_IPPROTO_NETMGMT
                && r.hop == next_hop
                && wanted.contains(&(r.dest, r.len))
                && on_interface.is_none_or(|index| index == r.ifindex)
        })
        .map(|r| (r.dest, r.len, r.ifindex))
        .collect()
}

/// How many of `batch`'s routes are currently in the live table.
pub fn bypass_routes_present(batch: &BypassBatch) -> usize {
    matching_routes(batch).len()
}

/// Remove a bypass batch: one table read, then delete each of our routes.
/// Returns how many were removed.
pub fn remove_bypass_routes_batch(batch: &BypassBatch) -> usize {
    let Ok(next_hop) = batch.next_hop.parse::<Ipv4Addr>() else {
        return 0;
    };
    let mut removed = 0usize;
    let mut gone = 0usize; // removed by someone else meanwhile
    let mut last_error = 0u32;
    for (dest, len, ifindex) in matching_routes(batch) {
        // SAFETY: the row is fully initialised.
        let row = forward_row(ifindex, dest, len, next_hop);
        match unsafe { DeleteIpForwardEntry2(&row) } {
            NO_ERROR => removed += 1,
            ERROR_NOT_FOUND => gone += 1,
            code => last_error = code,
        }
    }
    if last_error != NO_ERROR {
        tracing::warn!(
            removed,
            gone,
            last_error,
            of = batch.cidrs.len(),
            "some bypass routes could not be removed"
        );
    } else {
        tracing::info!(removed, gone, of = batch.cidrs.len(), "bypass routes removed");
    }
    removed
}

/// Persist the pending batch; [`clear_route_journal`] removes the file once
/// the routes are gone. Best effort — a missing journal only costs recovery.
pub fn write_route_journal(batch: &BypassBatch) {
    let written = serde_json::to_string(batch)
        .map_err(anyhow::Error::from)
        .and_then(|json| std::fs::write(journal_path(), json).map_err(anyhow::Error::from));
    if let Err(e) = written {
        tracing::warn!(error = %e, "could not write the route journal");
    }
}

pub fn clear_route_journal() {
    let _ = std::fs::remove_file(journal_path());
}

/// Remove bypass routes a previous run installed but never got to delete
/// (Task Manager kill, crash, power loss).
fn recover_route_journal() {
    let path = journal_path();
    let Ok(json) = std::fs::read_to_string(&path) else {
        return;
    };
    match serde_json::from_str::<BypassBatch>(&json) {
        Ok(batch) => {
            let removed = remove_bypass_routes_batch(&batch);
            tracing::info!(removed, "cleaned up bypass routes from an unclean exit");
        }
        Err(e) => tracing::warn!(error = %e, "unreadable route journal"),
    }
    clear_route_journal();
}

#[cfg(test)]
mod bulk_tests {
    use super::*;

    #[test]
    fn cidr_parsing() {
        let (ip, len) = parse_cidr("10.1.2.0/24").unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 1, 2, 0));
        assert_eq!(len, 24);
        assert!(parse_cidr("nonsense").is_none());
        assert!(parse_cidr("10.0.0.0").is_none());
    }

    /// `IN_ADDR` carries the address bytes in network order. Getting this
    /// wrong builds a byte-reversed route on delete, which silently removes
    /// nothing (it did, until the live test caught it).
    #[test]
    fn sockaddr_carries_the_address_bytes_in_order() {
        // None of these reads the same backwards.
        for ip in ["2.57.3.0", "91.107.0.1", "192.168.1.1"] {
            let ip: Ipv4Addr = ip.parse().unwrap();
            // SAFETY: the Ipv4 arm was the one written.
            let raw = unsafe { v4_sockaddr(ip).Ipv4.sin_addr.S_un.S_addr };
            assert_eq!(raw.to_ne_bytes(), ip.octets(), "write side of {ip}");
            assert_eq!(addr_from(raw), ip, "read side of {ip}");
            // The trap itself, spelled out: the big-endian reading is wrong.
            assert_ne!(Ipv4Addr::from(raw), ip, "test needs a non-palindrome");
        }
    }

    fn present(batch: &BypassBatch) -> usize {
        matching_routes(batch).len()
    }

    /// Round-trip against the live route table of the default interface.
    /// Uses TEST-NET-2 addresses via the gateway the default route already
    /// uses, so traffic is unaffected. Run from an elevated shell with
    /// `cargo test --release live_batch_roundtrip -- --ignored --nocapture`.
    #[test]
    #[ignore = "needs an elevated shell; adds and removes routes on the live default interface"]
    fn live_batch_roundtrip() {
        let orig = capture_default_route().unwrap();
        assert!(orig.is_usable(), "no usable default route on this machine");
        let next_hop: Ipv4Addr = orig.next_hop.parse().unwrap();
        let alias = orig.interface_alias.clone();

        // --- 200 documentation-range /32s --------------------------------
        let cidrs: Vec<String> = (0..200).map(|i| format!("198.51.100.{i}/32")).collect();
        let t0 = std::time::Instant::now();
        let batch = add_bypass_routes_batch(&alias, next_hop, &cidrs).unwrap();
        let add_ms = t0.elapsed().as_millis();
        println!("add 200 routes: {add_ms} ms");
        assert_eq!(batch.cidrs.len(), 200);
        assert_eq!(present(&batch), 200, "routes missing from the live table");

        // Do they live in the persistent store (i.e. survive a reboot)?
        let reg = Command::new("reg")
            .args([
                "query",
                r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes",
            ])
            .output()
            .unwrap();
        let reg_out = String::from_utf8_lossy(&reg.stdout) + String::from_utf8_lossy(&reg.stderr);
        println!(
            "PersistentRoutes registry mentions the test range: {}",
            reg_out.contains("198.51.100")
        );

        let t1 = std::time::Instant::now();
        let removed = remove_bypass_routes_batch(&batch);
        println!("remove 200 routes: {} ms", t1.elapsed().as_millis());
        assert_eq!(removed, 200);
        assert_eq!(present(&batch), 0, "routes still present after removal");

        // --- journal round-trip -------------------------------------------
        write_route_journal(&batch);
        assert!(journal_path().exists());
        clear_route_journal();
        assert!(!journal_path().exists());

        // --- the real geoip:ir rule set, through the user's rule compiler ---
        let config = crate::routing::RoutingConfig {
            rules: vec![crate::routing::Rule {
                name: "Iran".into(),
                enabled: true,
                outbound: crate::routing::Outbound::Direct,
                domains: vec![],
                ips: vec!["geoip:ir".into()],
            }],
            ..Default::default()
        };
        let split = config.tunnel_split().unwrap();
        println!(
            "geoip:ir: {} CIDRs after supernet merge",
            split.country_cidrs.len()
        );
        let t2 = std::time::Instant::now();
        let ir = add_bypass_routes_batch(&alias, next_hop, &split.country_cidrs).unwrap();
        let ir_add_ms = t2.elapsed().as_millis();
        println!(
            "add {} geoip:ir routes: {ir_add_ms} ms",
            ir.cidrs.len()
        );
        let n = present(&ir);
        let t3 = std::time::Instant::now();
        let ir_removed = remove_bypass_routes_batch(&ir);
        println!(
            "present {n}, removed {ir_removed} in {} ms",
            t3.elapsed().as_millis()
        );
        assert_eq!(ir_removed, ir.cidrs.len());
        assert_eq!(present(&ir), 0, "geoip:ir routes left behind");
    }

    /// Diagnostic for the live table: for the `geoip:ir` prefixes routed via
    /// the default gateway, count rows per matching condition and by age.
    /// With `RVPN_DELETE_YOUNGER_THAN_SECS=<n>` it also deletes the matching
    /// NetMgmt routes younger than `<n>` seconds — a recovery tool for routes
    /// whose journal was lost, NOT something a normal run ever does.
    #[test]
    #[ignore = "elevated shell; live route-table diagnostic / recovery tool"]
    fn live_probe_ir_routes() {
        let orig = capture_default_route().unwrap();
        assert!(orig.is_usable());
        let next_hop: Ipv4Addr = orig.next_hop.parse().unwrap();
        let index = interface_index(&orig.interface_alias).unwrap();
        let split = crate::routing::RoutingConfig {
            rules: vec![crate::routing::Rule {
                name: "Iran".into(),
                enabled: true,
                outbound: crate::routing::Outbound::Direct,
                domains: vec![],
                ips: vec!["geoip:ir".into()],
            }],
            ..Default::default()
        }
        .tunnel_split()
        .unwrap();
        let wanted = wanted_prefixes(&BypassBatch {
            cidrs: split.country_cidrs,
            ..Default::default()
        });
        let hop = next_hop;
        let routes = live_v4_routes().unwrap();

        let on_prefix: Vec<LiveRoute> = routes
            .iter()
            .copied()
            .filter(|r| wanted.contains(&(r.dest, r.len)))
            .collect();
        let via_gw = |r: &LiveRoute| r.hop == hop;
        let ours = |r: &LiveRoute| via_gw(r) && r.protocol == MIB_IPPROTO_NETMGMT;
        let ours_here = |r: &LiveRoute| ours(r) && r.ifindex == index;
        println!("routes in the table: {}; on an IR prefix: {}", routes.len(), on_prefix.len());
        println!("  + via the default gateway: {}", on_prefix.iter().filter(|r| via_gw(r)).count());
        println!("  + protocol NetMgmt:       {}", on_prefix.iter().filter(|r| ours(r)).count());
        println!("  + on interface {index}:        {}", on_prefix.iter().filter(|r| ours_here(r)).count());
        let younger = |secs: u32| on_prefix.iter().filter(|r| ours(r) && r.age < secs).count();
        println!(
            "  age (via gateway, NetMgmt): <10min={} <1h={} <6h={} <24h={} <7d={}",
            younger(600),
            younger(3600),
            younger(6 * 3600),
            younger(24 * 3600),
            younger(7 * 24 * 3600)
        );
        for r in on_prefix.iter().filter(|r| ours(r)).take(4) {
            println!("  sample {}/{} ifindex={} age={}s", r.dest, r.len, r.ifindex, r.age);
        }

        let Ok(max_age) = std::env::var("RVPN_DELETE_YOUNGER_THAN_SECS") else {
            return;
        };
        let max_age: u32 = max_age.parse().unwrap();
        let young: Vec<LiveRoute> = on_prefix
            .iter()
            .copied()
            .filter(|r| ours(r) && r.age < max_age)
            .collect();
        let mut removed = 0usize;
        for r in &young {
            // SAFETY: the row is fully initialised.
            let row = forward_row(r.ifindex, r.dest, r.len, next_hop);
            if unsafe { DeleteIpForwardEntry2(&row) } == NO_ERROR {
                removed += 1;
            }
        }
        println!("deleted {removed} of {} routes younger than {max_age}s", young.len());
    }
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
