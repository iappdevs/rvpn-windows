//! End-to-end test against a real rVPN server.
//!
//! Verifies the full protocol path WITHOUT needing Administrator rights:
//! identity + prekey → X3DH handshake → Double Ratchet → VirtualIp
//! assignment → and a real data round-trip (a crafted IPv4/UDP DNS query
//! injected exactly like the Wintun pump does, answered by 1.1.1.1 through
//! the server's NAT).
//!
//! Run with:
//! ```text
//! RVPN_TEST_SERVER=ws://host:port/api/v1/ws/tun cargo test --test e2e_server -- --ignored --nocapture
//! ```

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rvpn_mobile::ffi::TunConfig;
use rvpn_mobile::ios_tun::{IosTunClient, TunClientState};

const DEFAULT_SERVER: &str = "ws://91.107.154.88:8443/api/v1/ws/tun";

fn server_address() -> String {
    std::env::var("RVPN_TEST_SERVER").unwrap_or_else(|_| DEFAULT_SERVER.into())
}

/// IPv4 header checksum (RFC 1071).
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            (chunk[0] as u16) << 8
        };
        sum = sum.wrapping_add(word as u32);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build one IPv4/UDP packet carrying `payload` (UDP checksum 0 — legal for IPv4).
fn build_udp_packet(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;

    let mut packet = vec![0u8; total_len];
    // IPv4 header
    packet[0] = 0x45; // version 4, IHL 5
    packet[1] = 0x00; // DSCP/ECN
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&0x1234u16.to_be_bytes()); // id
    packet[6..8].copy_from_slice(&0u16.to_be_bytes()); // no fragmentation
    packet[8] = 64; // TTL
    packet[9] = 17; // UDP
    packet[10..12].copy_from_slice(&0u16.to_be_bytes()); // checksum filled below
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    let checksum = ipv4_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    // UDP header
    packet[20..22].copy_from_slice(&sport.to_be_bytes());
    packet[22..24].copy_from_slice(&dport.to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[26..28].copy_from_slice(&0u16.to_be_bytes()); // checksum 0 (optional)

    packet[28..].copy_from_slice(payload);
    packet
}

/// Minimal DNS A query for `name`.
fn build_dns_query(name: &str) -> Vec<u8> {
    let mut q = vec![0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&1u16.to_be_bytes()); // A
    q.extend_from_slice(&1u16.to_be_bytes()); // IN
    q
}

#[test]
#[ignore = "needs a live rVPN server (RVPN_TEST_SERVER env to override)"]
fn full_tunnel_roundtrip() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,rvpn_mobile=debug".into()),
        )
        .with_target(false)
        .try_init();

    let dir = tempfile::tempdir().expect("tempdir");
    let identity_path = dir.path().join("identity.key");
    let prekey_path = dir.path().join("prekey-bundle.json");

    // Client identity + server prekey bundle.
    let identity = rvpn_core::crypto::IdentityKey::generate();
    identity.save(&identity_path).expect("save identity");
    std::fs::write(
        &prekey_path,
        r#"{
  "identity_key": "QCFBNfqMos1kbcky3J6JCQp7nf3GDZiWkH6SxfF1rjg=",
  "identity_x25519_key": "2j70UJ0BcvJcZooixbqM4FT6khzQzdJsTcZK5PG1d3I=",
  "signed_prekey": "a2mJO5dRiAIyuaklS4BAbLWyPpEHR8TmanWswHPqkDY=",
  "prekey_signature": "q0eyXK5AzEF7fisUM3/oaNU8ZSIA8EgBVvBtQx2/vqFSRt5IUIQ3oYt9ACKDc0/M7hjxUFXJxo1IMbh5L0dZBg==",
  "one_time_prekey": null,
  "identity_key_version": 1,
  "rotation_signature": null
}"#,
    )
    .expect("write prekey bundle");

    let config = TunConfig {
        server_address: server_address(),
        identity_key_path: identity_path.to_string_lossy().into_owned(),
        prekey_bundle_path: prekey_path.to_string_lossy().into_owned(),
        dns_servers: vec!["1.1.1.1".into()],
        bypass_networks: Vec::new(),
        mtu: 1420,
        split_tunnel_enabled: false,
        builtin_bypass_countries: Vec::new(),
        bypass_domains: Vec::new(),
        tunnel_domains: Vec::new(),
        block_ads: true,
        dns_bind_addr: "127.0.0.1:5353".into(),
        enable_dns_proxy: false, // not needed for this test
        stealth_fingerprint: None,
        server_identity_pin: None, // TOFU capture mode
        country_ips_file: None,
        extra_servers: Vec::new(),
        routing: std::collections::HashMap::new(),
    };

    // Runtime + engine, mirroring engine.rs's lifecycle.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");

    let client = IosTunClient::new(&config, runtime.handle().clone()).expect("engine init (X3DH setup)");
    let client = Arc::new(client);
    let pin = client.server_identity_pin().to_string();
    println!("server pin: {pin}");
    assert!(pin.starts_with("ik:1:"), "canonical TOFU pin expected");

    client.set_reconnect_enabled(true); // the connect loop itself is gated on this
    client.start();

    // Wait for Connected + virtual IP.
    let deadline = Instant::now() + Duration::from_secs(20);
    let (src_ip, mtu) = loop {
        match client.get_state() {
            TunClientState::Connected | TunClientState::IpAssigned => {
                let ip = client
                    .get_tunnel_ip()
                    .and_then(|s| s.parse::<Ipv4Addr>().ok())
                    .expect("virtual IP assigned");
                let mtu = client.get_mtu();
                break (ip, mtu);
            }
            TunClientState::Error => panic!("engine error state"),
            _ if Instant::now() > deadline => panic!("timeout waiting for connect"),
            _ => std::thread::sleep(Duration::from_millis(100)),
        }
    };
    println!("connected: tunnel ip {src_ip}, mtu {mtu}");

    // Inject a real DNS query to 1.1.1.1 through the tunnel — exactly the
    // way the Wintun uplink pump does it.
    let query = build_dns_query("example.com");
    let packet = build_udp_packet(src_ip, "1.1.1.1".parse().unwrap(), 40000, 53, &query);
    client
        .try_send_packet(packet)
        .expect("uplink send (encrypted to server, NAT'ed to 1.1.1.1)");

    // Expect the answer to come back down the tunnel. Poll directly —
    // wait_for_packet's notify can race with a drained receiver.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        while let Some(response) = client.recv_packet_from_server() {
            if response.len() < 28 || response[9] != 17 {
                continue; // not IPv4/UDP (e.g. some control frame)
            }
            let sport = u16::from_be_bytes([response[20], response[21]]);
            if sport != 53 {
                continue;
            }
            // A DNS answer has QR=1 and at least one answer (or the
            // rcode set). Parse enough to prove it is a real reply.
            let dns = &response[28..];
            assert!(dns.len() >= 12, "DNS header present");
            let flags = u16::from_be_bytes([dns[2], dns[3]]);
            let answers = u16::from_be_bytes([dns[6], dns[7]]);
            println!(
                "DNS reply: flags={flags:#06x} answers={answers} bytes={}",
                response.len()
            );
            assert_eq!(flags & 0x8000, 0x8000, "QR bit set (it is a response)");
            println!("E2E PASS: query relayed through the server and answered");
            client.stop();
            return;
        }
        if Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("no DNS answer came back through the tunnel within 10s");
}
