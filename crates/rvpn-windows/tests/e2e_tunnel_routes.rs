//! Live, elevated end-to-end test of full-tunnel routing on this machine.
//!
//! Uses the real profile under `%APPDATA%\rvpn-windows` and the live server,
//! so it brings the tunnel up for a few seconds and changes the system's
//! routes/DNS while it runs. Everything it installs is removed again, and a
//! failure calls the same startup self-healing the app uses.
//!
//! Run from an elevated shell:
//!
//! ```text
//! cargo test --release --test e2e_tunnel_routes -- --ignored --nocapture --test-threads=1
//! ```

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use rvpn_windows::engine::{EngineEvent, EngineHandle, EnginePhase};
use rvpn_windows::profile::{ConnMode, Profile, ProfileStore};
use rvpn_windows::routing::RoutingConfig;
use rvpn_windows::winroute::{self, BypassBatch};

/// Everything the app cleans up on a normal start.
fn self_heal() {
    winroute::sweep_stale_state();
    rvpn_windows::sysproxy::sweep_stale_system_proxy();
}

/// Engine logs on stdout, plus a last-resort exit: this test deliberately
/// probes code paths that used to hang, and the process owns the tunnel.
fn init(max_secs: u64) {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init()
        .ok();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(max_secs));
        eprintln!("
WATCHDOG: the test did not finish in {max_secs} s — cleaning up and exiting");
        self_heal();
        std::process::exit(99);
    });
}

/// The user's first profile, switched to tunnel mode IN MEMORY — the test
/// never writes `profiles.json`, whatever mode it is saved in.
fn tunnel_profile() -> Profile {
    let mut profile = ProfileStore::load()
        .expect("read profiles.json under %APPDATA%")
        .into_iter()
        .next()
        .expect("no profile in %APPDATA%\rvpn-windows");
    println!(
        "profile '{}' (saved mode {:?}), server {}",
        profile.slug, profile.mode, profile.server_address
    );
    profile.mode = ConnMode::Tun;
    profile
}

/// The bypass batch the engine installs for `profile` — used as a probe for
/// "are any of these routes in the table right now?".
fn probe_for(profile: &Profile) -> (BypassBatch, Vec<String>) {
    let split = RoutingConfig::from_profile(profile)
        .tunnel_split()
        .expect("routing rules compile");
    let orig = winroute::capture_default_route().expect("read the default route");
    let cidrs = split.country_cidrs.clone();
    (
        BypassBatch {
            interface_alias: orig.interface_alias.clone(),
            next_hop: orig.next_hop.clone(),
            cidrs,
            preexisting: 0,
        },
        split.country_cidrs,
    )
}

fn ps(script: &str) -> String {
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .expect("start powershell");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The source address the system picks for `dest` — the kernel's own route
/// decision, with no packet sent.
fn source_ip_for(dest: Ipv4Addr) -> std::io::Result<Ipv4Addr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    sock.connect((dest, 53))?;
    match sock.local_addr()?.ip().to_canonical() {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(ip) => Err(std::io::Error::other(format!(
            "IPv6 source {ip} for an IPv4 destination"
        ))),
    }
}

/// How long until the kernel routes `dest` from `want`. Routing settles
/// shortly after an adapter comes up, so the first instants are expected to
/// miss; what matters is that it settles at all, and how soon.
fn settle_time(dest: Ipv4Addr, want: Ipv4Addr, what: &str) -> Duration {
    let started = Instant::now();
    let mut misses = 0;
    let mut last = None;
    loop {
        match source_ip_for(dest) {
            Ok(ip) if ip == want => {
                println!(
                    "{what}: routed from {want} {} ms after the check started ({} earlier misses)",
                    started.elapsed().as_millis(),
                    misses
                );
                return started.elapsed();
            }
            other => {
                misses += 1;
                if misses == 1 {
                    // What the adapter looks like while the kernel refuses.
                    println!("--- adapter state at the first miss ---");
                    for query in [
                        "Get-NetAdapter -Name 'R-VPN' | Format-List Status,MediaConnectionState,AdminStatus",
                        "Get-NetIPAddress -InterfaceAlias 'R-VPN' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Format-Table IPAddress,PrefixLength,AddressState,PrefixOrigin,SkipAsSource",
                        "Get-NetRoute -InterfaceAlias 'R-VPN' -ErrorAction SilentlyContinue | Format-Table DestinationPrefix,NextHop,RouteMetric,State",
                    ] {
                        println!("{}", ps(query));
                    }
                }
                last = Some(other);
            }
        }
        if started.elapsed() > Duration::from_secs(12) {
            println!("--- routing state at the failure ---");
            for query in [
                "Get-NetAdapter -Name 'R-VPN' | Format-List Name,Status,MediaConnectionState,ifIndex",
                "Get-NetIPAddress -InterfaceAlias 'R-VPN' -ErrorAction SilentlyContinue | Format-Table IPAddress,PrefixLength,AddressState,SkipAsSource",
                "Get-NetRoute -InterfaceAlias 'R-VPN' -ErrorAction SilentlyContinue | Format-Table DestinationPrefix,NextHop,RouteMetric,Protocol",
                "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Format-Table InterfaceAlias,NextHop,RouteMetric",
            ] {
                println!("{}", ps(query));
            }
            panic!(
                "{what}: still not routed from {want} after 12 s; last answer was {last:?}"
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn v4(text: &str) -> Ipv4Addr {
    text.trim().parse().expect("an IPv4 address")
}

fn curl(args: &[&str]) -> String {
    let out = Command::new("curl.exe")
        .args(args)
        .output()
        .expect("start curl.exe");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    )
}

fn resolve(host: &str) -> Vec<IpAddr> {
    (host, 443)
        .to_socket_addrs()
        .map(|it| it.map(|a| a.ip()).filter(IpAddr::is_ipv4).collect())
        .unwrap_or_default()
}

/// Stops the tunnel and runs the startup self-healing when the test
/// unwinds, so a failed assertion can never leave the machine tunnelled.
struct StopOnDrop<'a>(&'a EngineHandle);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.stop_and_wait();
        self_heal();
    }
}

fn host_of(url: &str) -> String {
    url.trim_start_matches("wss://")
        .trim_start_matches("ws://")
        .split(['/', ':'])
        .next()
        .unwrap_or_default()
        .to_string()
}

/// Nothing of ours left on the NIC or on disk: we are back to `baseline`
/// matching routes. (This machine carries hundreds of unrelated Iranian
/// routes from another tool — routes that existed before us are not ours
/// to remove.) The adapter disappears asynchronously, so give it a few
/// seconds before calling it a leak.
fn assert_clean(probe: &BypassBatch, baseline: usize) {
    let deadline = Instant::now() + Duration::from_secs(8);
    let adapter = loop {
        let adapter = ps("@(Get-NetAdapter -Name 'R-VPN' -ErrorAction SilentlyContinue).Count").trim() == "1";
        let clean = !adapter
            && !winroute::journal_path().exists()
            && winroute::bypass_routes_present(probe) == baseline;
        if !clean && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(500));
            continue;
        }
        break adapter;
    };
    let present = winroute::bypass_routes_present(probe);
    assert_eq!(present, baseline, "bypass routes left behind");
    assert!(
        !winroute::journal_path().exists(),
        "route journal left behind: {}",
        winroute::journal_path().display()
    );
    assert!(!adapter, "the R-VPN adapter outlived the session");
}

/// Connect on a worker thread and cancel after `after` — what Disconnect and
/// Quit do. Returns how long the worker and the teardown needed afterwards,
/// whether the tunnel had already come up, and whether the cancel actually
/// landed while the connect was still running.
fn cancel_during_connect(profile: &Profile, after: Duration) -> (Duration, bool, bool) {
    let (tx, rx) = mpsc::channel::<EngineEvent>();
    let cancel = Arc::new(AtomicBool::new(false));
    let (p, flag) = (profile.clone(), cancel.clone());
    let worker = std::thread::spawn(move || EngineHandle::connect_cancellable(&p, tx, flag));
    std::thread::sleep(after);

    let mid_connect = !worker.is_finished();
    let asked = Instant::now();
    cancel.store(true, Ordering::SeqCst);
    let engine = worker.join().expect("connect worker panicked");
    let phase = engine.snapshot().phase;
    // A cancelled connect ends Idle; Failed means it died on its own and
    // this run proved nothing about stopping.
    if let EnginePhase::Failed { reason } = phase {
        panic!("the connect failed on its own (offset {after:?}): {reason}");
    }
    let was_up = matches!(phase, EnginePhase::Connected { .. });
    engine.stop_and_wait();
    drop(rx);
    (asked.elapsed(), was_up, mid_connect)
}

/// The trace the user hit at 18:20:53 ("connection cancelled", then an app
/// that would not go away): stop at several points of the startup sequence.
#[test]
#[ignore = "elevated shell, live server; repeatedly starts and cancels a tunnel"]
fn live_cancel_during_connect_leaves_nothing_behind() {
    init(150);
    let profile = tunnel_profile();
    let (probe, _) = probe_for(&profile);
    self_heal();
    let baseline = winroute::bypass_routes_present(&probe);
    println!("routes matching the rules before the test: {baseline}");

    let mut mid_connect_hits = 0;
    for after_ms in [200u64, 800, 1500, 2500, 4000] {
        let (took, was_up, mid_connect) =
            cancel_during_connect(&profile, Duration::from_millis(after_ms));
        mid_connect_hits += usize::from(mid_connect);
        println!(
            "stop after {after_ms:>4} ms: still connecting = {mid_connect:<5} already up = {was_up:<5} finished in {:>5} ms",
            took.as_millis()
        );
        assert!(
            took < Duration::from_secs(10),
            "stop after a cancel at {after_ms} ms took {took:?}"
        );
        assert_clean(&probe, baseline);
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(
        mid_connect_hits >= 3,
        "only {mid_connect_hits} of 5 stops landed mid-connect — the test did not exercise the cancel path"
    );
}

/// The user's case: full tunnel with a `geoip:ir` rule — Iranian traffic
/// direct, everything else through the tunnel, and a clean, fast stop.
#[test]
#[ignore = "elevated shell, live server; brings the tunnel up for a few seconds"]
fn live_full_tunnel_with_geoip_ir() {
    init(240);
    let profile = tunnel_profile();
    let (probe, cidrs) = probe_for(&profile);
    assert!(!cidrs.is_empty(), "the profile has no Direct GeoIP rule to test");
    let (physical, server_host) = (probe.interface_alias.clone(), host_of(&profile.server_address));
    let direct_source = source_ip_for(v4("8.8.8.8")).expect("route lookup without the tunnel");
    println!("without the tunnel, traffic to 8.8.8.8 leaves from {direct_source} ('{physical}')");
    println!(
        "profile '{}' on '{physical}': {} bypass routes from the routing rules",
        profile.slug,
        cidrs.len()
    );
    self_heal();
    let baseline = winroute::bypass_routes_present(&probe);
    println!("routes matching the rules before the test: {baseline} (pre-existing, left alone)");
    assert_clean(&probe, baseline);

    // --- connect -------------------------------------------------------------
    let (tx, rx) = mpsc::channel::<EngineEvent>();
    let cancel = Arc::new(AtomicBool::new(false));
    let (p, flag) = (profile.clone(), cancel.clone());
    let started = Instant::now();
    let worker = std::thread::spawn(move || EngineHandle::connect_cancellable(&p, tx, flag));
    let engine = loop {
        if worker.is_finished() {
            break worker.join().expect("connect worker panicked");
        }
        if started.elapsed() > Duration::from_secs(90) {
            cancel.store(true, Ordering::SeqCst);
            panic!("connect did not finish within 90 s");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let connect = started.elapsed();
    match engine.snapshot().phase {
        EnginePhase::Connected { ip, .. } => println!("connected as {ip} in {} ms", connect.as_millis()),
        other => {
            self_heal();
            panic!("connect ended in {other:?} after {connect:?}");
        }
    }
    assert!(
        connect < Duration::from_secs(15),
        "connect took {connect:?} — one netsh per CIDR would take ~5 min"
    );

    let _stop = StopOnDrop(&engine);

    // --- what is installed ---------------------------------------------------
    let batch: BypassBatch = serde_json::from_str(
        &std::fs::read_to_string(winroute::journal_path()).expect("journal written on connect"),
    )
    .expect("journal parses");
    let ours = winroute::bypass_routes_present(&batch);
    let total = winroute::bypass_routes_present(&probe);
    println!(
        "{} routes from the rules: {} pre-existing, {} installed by this connect;          {ours} of ours and {total} in total are in the live table",
        cidrs.len(),
        batch.preexisting,
        batch.cidrs.len()
    );
    assert_eq!(ours, batch.cidrs.len(), "journal and route table disagree");
    assert_eq!(total, baseline + batch.cidrs.len(), "the whole rule set must be routed around the tunnel");

    // --- where traffic goes --------------------------------------------------
    let EnginePhase::Connected { ip: tunnel_ip, .. } = engine.snapshot().phase else {
        unreachable!("checked above")
    };
    let tunnel_ip = v4(&tunnel_ip);
    assert_ne!(tunnel_ip, direct_source);
    settle_time(v4("8.8.8.8"), tunnel_ip, "8.8.8.8 (foreign)");
    settle_time(v4("1.1.1.1"), tunnel_ip, "1.1.1.1 (foreign)");

    let inside = |ip: Ipv4Addr| {
        cidrs.iter().any(|c| {
            c.parse::<ip_network::IpNetwork>()
                .is_ok_and(|net| net.contains(IpAddr::V4(ip)))
        })
    };
    let mellat = resolve("ebanking.mellat.ir");
    println!("ebanking.mellat.ir resolves to {mellat:?}");
    assert!(!mellat.is_empty(), "the bank's name did not resolve through the tunnel");
    for ip in mellat.iter().filter(|ip| ip.is_ipv4()) {
        let ip = v4(&ip.to_string());
        settle_time(ip, direct_source, &format!("ebanking.mellat.ir ({ip}, in geoip:ir = {})", inside(ip)));
    }

    let bank = curl(&[
        "-s", "-m", "25", "-o", "NUL",
        "-w", "%{http_code} (remote %{remote_ip})",
        "https://ebanking.mellat.ir/",
    ]);
    println!("https://ebanking.mellat.ir/ -> HTTP {bank}");
    assert!(bank.starts_with("200") || bank.starts_with("3"), "bank page did not load");

    let exit = curl(&["-s", "-m", "25", "https://api.ipify.org"]);
    let server_ip = resolve(&server_host).first().cloned();
    println!("public exit IP for foreign sites: {exit:?} (server {server_ip:?})");
    assert_eq!(
        exit.parse::<IpAddr>().ok(),
        server_ip,
        "foreign traffic is not exiting through the server"
    );

    let stats = engine.snapshot();
    println!(
        "through the engine: {} bytes up, {} bytes down",
        stats.tx_bytes, stats.rx_bytes
    );
    assert!(stats.tx_bytes > 0 && stats.rx_bytes > 0, "no packets crossed the tunnel");
    drop(rx);

    // --- stop ----------------------------------------------------------------
    let asked = Instant::now();
    drop(_stop);
    println!("stop + teardown took {} ms", asked.elapsed().as_millis());
    assert!(
        asked.elapsed() < Duration::from_secs(15),
        "teardown took {:?}",
        asked.elapsed()
    );
    assert_clean(&probe, baseline);
    settle_time(v4("8.8.8.8"), direct_source, "8.8.8.8 after the stop");

    // --- Task Manager kill, simulated: what the next start cleans up ---------
    // Documentation-range addresses: guaranteed not to pre-exist.
    let sample: Vec<String> = (0..20).map(|i| format!("198.51.100.{i}/32")).collect();
    let next_hop = probe.next_hop.parse().expect("default gateway");
    let orphan = winroute::add_bypass_routes_batch(&physical, next_hop, &sample)
        .expect("install a sample batch");
    winroute::write_route_journal(&orphan);
    assert_eq!(winroute::bypass_routes_present(&orphan), orphan.cidrs.len());
    self_heal();
    assert_eq!(winroute::bypass_routes_present(&orphan), 0, "startup did not recover the orphaned routes");
    assert!(!winroute::journal_path().exists());
}
