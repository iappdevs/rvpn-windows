//! Live test for SOCKS5 proxy mode against a real rVPN server.
//!
//! Verifies BOTH data paths:
//! 1. a normal host exits through the server (tunnel);
//! 2. a bypass-ruled host (domain rule + custom IR IP database) goes
//!    direct over the normal internet — proven by a different exit IP.
//!
//! Run:
//! ```text
//! RVPN_TEST_SERVER=wss://host:8443/api/v1/ws/tun cargo test --release --no-default-features --test e2e_proxy -- --ignored --nocapture
//! ```

use std::sync::mpsc;
use std::time::{Duration, Instant};

use rvpn_windows::engine::{EngineEvent, EngineHandle, EnginePhase};
use rvpn_windows::profile::{ConnMode, Profile};

fn server_address() -> String {
    std::env::var("RVPN_TEST_SERVER")
        .unwrap_or_else(|_| "wss://dl.99aa.ir:8443/api/v1/ws/tun".into())
}

fn pick_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Minimal SOCKS5 CONNECT + HTTP/1.0 GET through the local proxy.
fn socks5_http_get(proxy_port: u16, host: &str, path: &str) -> String {
    use std::io::{Read, Write};

    let mut s = std::net::TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect proxy");
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();

    let hostb = host.as_bytes();
    let req = vec![0x05, 0x01, 0x00];
    s.write_all(&req).unwrap();
    let mut b = [0u8; 2];
    s.read_exact(&mut b).unwrap();
    assert_eq!(b[0], 0x05, "SOCKS5 greeting");

    let mut conn = vec![0x05, 0x01, 0x00, 0x03, hostb.len() as u8];
    conn.extend_from_slice(hostb);
    conn.extend_from_slice(&80u16.to_be_bytes());
    s.write_all(&conn).unwrap();
    let mut resp = [0u8; 4];
    s.read_exact(&mut resp).unwrap();
    assert_eq!(resp[1], 0x00, "SOCKS5 CONNECT accepted");
    // bound address (var-int) — consume the rest of the header
    match resp[3] {
        0x01 => {
            let mut rest = [0u8; 4 + 2];
            s.read_exact(&mut rest).unwrap();
        }
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).unwrap();
            let mut rest = vec![0u8; l[0] as usize + 2];
            s.read_exact(&mut rest).unwrap();
        }
        0x04 => {
            let mut rest = [0u8; 16 + 2];
            s.read_exact(&mut rest).unwrap();
        }
        other => panic!("unexpected SOCKS5 address type {other:#x}"),
    }

    let http = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: curl\r\n\r\n");
    s.write_all(http.as_bytes()).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

fn extract_ip(http: &str) -> String {
    // both ipify and ifconfig answer with the bare IP in the body
    let body = http.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or(http);
    body.trim().to_string()
}

#[test]
#[ignore = "needs a live rVPN server"]
fn proxy_mode_tunnel_and_bypass() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,rvpn_mobile=debug".into()),
        )
        .with_target(false)
        .try_init();

    // Profile material lives inside the profile directory (slug-based paths).
    let mut profile = Profile::new("proxy e2e");
    let pdir = rvpn_windows::paths::profile_dir(&profile.slug);
    std::fs::create_dir_all(&pdir).unwrap();
    rvpn_windows::identity::generate_identity(&pdir.join("identity.key")).unwrap();
    std::fs::write(
        pdir.join("prekey-bundle.json"),
        include_str!("../../../assets/dl99aa-prekey.json"),
    )
    .unwrap();
    std::fs::write(
        pdir.join("country-ips.json"),
        include_str!("../../../assets/ir-cidrs.json"),
    )
    .unwrap();

    let port = pick_free_port();
    profile.mode = ConnMode::Proxy;
    profile.proxy_port = port;
    profile.server_address = server_address();
    profile.split_tunnel_enabled = true;
    profile.builtin_bypass_countries = vec!["IR".into()];
    // BOTH probe hosts are bypass-ruled for the direct test below; the
    // tunnel probe is re-run through a non-bypassed host.
    profile.bypass_domains = vec!["icanhazip.com".into()];
    profile.country_ips_file = Some("country-ips.json".into());
    // No stored pin: TOFU capture fires on success (asserted implicitly).

    let (tx, rx) = mpsc::channel::<EngineEvent>();
    let connect_handle = std::thread::spawn(move || EngineHandle::connect(&profile, tx));

    // Wait for Connected.
    let deadline = Instant::now() + Duration::from_secs(40);
    let mut connected = false;
    while Instant::now() < deadline {
        match rx.try_recv() {
            Ok(EngineEvent::Phase(EnginePhase::Connected { .. })) => {
                connected = true;
                break;
            }
            Ok(EngineEvent::Phase(EnginePhase::Failed { reason })) => {
                panic!("proxy connect failed: {reason}");
            }
            Ok(_) => {}
            Err(mpsc::TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(100)),
            Err(mpsc::TryRecvError::Disconnected) => break,
        }
    }
    assert!(connected, "proxy mode did not reach Connected");

    // Path A — NO bypass rule: the exit IP must be the SERVER's.
    let tun_http = socks5_http_get(port, "api.ipify.org", "/");
    let tun_ip = extract_ip(&tun_http);
    println!("exit via tunnel: {tun_ip}");

    // Path B — bypassed host (icanhazip.com is in bypass_domains): the exit
    // must be the local/normal internet, i.e. DIFFERENT from the server.
    let dir_http = socks5_http_get(port, "icanhazip.com", "/ip");
    let direct_ip = extract_ip(&dir_http);
    println!("exit via bypass (direct): {direct_ip}");

    let engine = connect_handle.join().unwrap();
    engine.stop();

    // Assertions: both paths answered with an IP, they differ, and the
    // bypass exit is NOT the server (that would mean the rule was ignored).
    assert!(
        tun_ip.parse::<std::net::Ipv4Addr>().is_ok(),
        "tunnel path did not return an IP: {tun_http:?}"
    );
    assert!(
        direct_ip.parse::<std::net::Ipv4Addr>().is_ok(),
        "bypass path did not return an IP: {dir_http:?}"
    );
    assert_ne!(tun_ip, direct_ip, "bypass did not take a different path!");
    assert_ne!(
        direct_ip, "91.107.154.88",
        "bypassed host went through the server — rule not applied!"
    );
    println!(
        "E2E PROXY PASS — tunnel exits via {tun_ip}, bypass exits via {direct_ip} (direct internet)"
    );
}

/// Minimal SOCKS4a CONNECT + HTTP GET through the local proxy (the dialect
/// Windows' system proxy actually speaks).
fn socks4_http_get(proxy_port: u16, host: &str, path: &str) -> String {
    use std::io::{Read, Write};

    let mut s = std::net::TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect proxy");
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();

    // SOCKS4a: [VER=4][CMD=1][PORT][0.0.0.x][USERID\0][DOMAIN\0]
    let mut req = vec![0x04, 0x01];
    req.extend_from_slice(&80u16.to_be_bytes());
    req.extend_from_slice(&[0, 0, 0, 1]); // 4a marker
    req.push(0); // empty user id
    req.extend_from_slice(host.as_bytes());
    req.push(0);
    s.write_all(&req).unwrap();

    let mut resp = [0u8; 8];
    s.read_exact(&mut resp).unwrap();
    assert_eq!(resp[1], 0x5A, "SOCKS4 CONNECT granted");

    let http = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: curl\r\n\r\n");
    s.write_all(http.as_bytes()).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

#[test]
#[ignore = "needs a live rVPN server"]
fn proxy_mode_socks4_system_dialect() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .try_init();

    let mut profile = Profile::new("proxy e2e s4");
    let pdir = rvpn_windows::paths::profile_dir(&profile.slug);
    std::fs::create_dir_all(&pdir).unwrap();
    rvpn_windows::identity::generate_identity(&pdir.join("identity.key")).unwrap();
    std::fs::write(
        pdir.join("prekey-bundle.json"),
        include_str!("../../../assets/dl99aa-prekey.json"),
    )
    .unwrap();

    let port = pick_free_port();
    profile.mode = ConnMode::Proxy;
    profile.proxy_port = port;
    profile.server_address = server_address();

    let (tx, rx) = mpsc::channel::<EngineEvent>();
    let connect_handle = std::thread::spawn(move || EngineHandle::connect(&profile, tx));

    let deadline = Instant::now() + Duration::from_secs(40);
    let mut connected = false;
    while Instant::now() < deadline {
        match rx.try_recv() {
            Ok(EngineEvent::Phase(EnginePhase::Connected { .. })) => {
                connected = true;
                break;
            }
            Ok(EngineEvent::Phase(EnginePhase::Failed { reason })) => {
                panic!("proxy connect failed: {reason}");
            }
            Ok(_) => {}
            Err(mpsc::TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(100)),
            Err(mpsc::TryRecvError::Disconnected) => break,
        }
    }
    assert!(connected, "proxy mode did not reach Connected");

    let http = socks4_http_get(port, "api.ipify.org", "/");
    let ip = extract_ip(&http);
    let engine = connect_handle.join().unwrap();
    engine.stop();
    assert!(
        ip.parse::<std::net::Ipv4Addr>().is_ok(),
        "SOCKS4 path returned nothing useful: {http:?}"
    );
    assert_ne!(ip, "127.0.0.1");
    println!("E2E SOCKS4 PASS — system dialect exits via {ip}");
}

#[test]
#[ignore = "needs a live rVPN server"]
fn proxy_counters_are_cumulative() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .try_init();

    // Skip when the user's running GUI owns the system proxy (its backup
    // guard / cleanup helper would reject a second session).
    if rvpn_windows::paths::app_data_dir()
        .join("sysproxy-backup.json")
        .exists()
    {
        eprintln!("SKIP: another proxy session is active");
        return;
    }

    let mut profile = Profile::new("proxy e2e counters");
    let pdir = rvpn_windows::paths::profile_dir(&profile.slug);
    std::fs::create_dir_all(&pdir).unwrap();
    rvpn_windows::identity::generate_identity(&pdir.join("identity.key")).unwrap();
    std::fs::write(
        pdir.join("prekey-bundle.json"),
        include_str!("../../../assets/dl99aa-prekey.json"),
    )
    .unwrap();

    let port = pick_free_port();
    profile.mode = ConnMode::Proxy;
    profile.proxy_port = port;
    profile.server_address = server_address();

    let (tx, rx) = mpsc::channel::<EngineEvent>();
    let connect_handle = std::thread::spawn(move || EngineHandle::connect(&profile, tx));

    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        match rx.try_recv() {
            Ok(EngineEvent::Phase(EnginePhase::Connected { .. })) => break,
            Ok(EngineEvent::Phase(EnginePhase::Failed { reason })) => {
                panic!("proxy connect failed: {reason}")
            }
            Ok(_) => {}
            Err(mpsc::TryRecvError::Empty) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100))
            }
            _ => panic!("proxy mode did not reach Connected"),
        }
    }
    let engine = connect_handle.join().unwrap();

    // Two sequential tunnelled requests; the session counters must GROW
    // across them, not reset per request.
    let _ = socks5_http_get(port, "api.ipify.org", "/");
    std::thread::sleep(Duration::from_millis(300));
    let snap1 = engine.snapshot();
    assert!(snap1.rx_bytes > 0 && snap1.tx_bytes > 0, "counters at zero after first request");

    let _ = socks5_http_get(port, "example.com", "/");
    std::thread::sleep(Duration::from_millis(300));
    let snap2 = engine.snapshot();

    engine.stop();
    assert!(
        snap2.rx_bytes > snap1.rx_bytes && snap2.tx_bytes > snap1.tx_bytes,
        "counters are not cumulative: after1 rx={} tx={} / after2 rx={} tx={}",
        snap1.rx_bytes, snap1.tx_bytes, snap2.rx_bytes, snap2.tx_bytes
    );
    println!(
        "COUNTERS PASS — cumulative session totals: up {} B, down {} B",
        snap2.tx_bytes, snap2.rx_bytes
    );
}
