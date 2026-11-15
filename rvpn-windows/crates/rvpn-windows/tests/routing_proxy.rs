//! Deterministic routing and mixed-inbound tests. Loopback only: no server
//! credentials, Internet access, registry changes or system-proxy activation.
use rvpn_windows::{profile::Profile, proxy::MixedProxy, routing::*};
use std::{collections::BTreeMap, net::IpAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
};

fn rule(action: Outbound, domains: &[&str], ips: &[&str]) -> Rule {
    Rule {
        name: format!("{action:?} rule"),
        outbound: action,
        domains: domains.iter().map(|v| v.to_string()).collect(),
        ips: ips.iter().map(|v| v.to_string()).collect(),
        ..Rule::default()
    }
}
fn router(config: RoutingConfig) -> Router {
    Router::build(config, &BTreeMap::new(), &[]).unwrap()
}
fn ips(values: &[&str]) -> Vec<IpAddr> {
    values.iter().map(|v| v.parse().unwrap()).collect()
}

#[test]
fn bundled_iran_ipv4_and_ipv6_work_without_import() {
    let r = router(RoutingConfig::iran_direct());
    assert_eq!(r.evaluate("5.160.0.1", &[]).outbound, Outbound::Direct);
    assert_eq!(r.evaluate("2a01:5ec0::1", &[]).outbound, Outbound::Direct);
    assert_eq!(
        r.evaluate("example.net", &ips(&["5.160.0.1"])).outbound,
        Outbound::Direct
    );
    assert_eq!(
        r.evaluate("example.net", &ips(&["8.8.8.8"])).outbound,
        Outbound::Proxy
    );
    assert_eq!(r.evaluate("BANK.IR.", &[]).outbound, Outbound::Direct);
    assert!(country_codes().contains(&"IR".to_string()));
    assert!(country_codes().contains(&"US".to_string()));
    assert!(country_codes().len() > 200);
}

#[test]
fn order_and_domain_strategies_follow_v2ray() {
    let mut c = RoutingConfig {
        rules: vec![
            rule(Outbound::Direct, &[], &["geoip:ir"]),
            rule(Outbound::Proxy, &["domain:example.com"], &[]),
        ],
        ..RoutingConfig::default()
    };
    assert_eq!(
        router(c.clone())
            .evaluate("www.example.com", &ips(&["5.160.0.1"]))
            .outbound,
        Outbound::Proxy
    );
    c.strategy = DomainStrategy::IPOnDemand;
    assert_eq!(
        router(c.clone())
            .evaluate("www.example.com", &ips(&["5.160.0.1"]))
            .outbound,
        Outbound::Direct
    );
    c.strategy = DomainStrategy::AsIs;
    assert_eq!(
        router(c)
            .evaluate("other.net", &ips(&["5.160.0.1"]))
            .outbound,
        Outbound::Proxy
    );
    let c = RoutingConfig {
        rules: vec![
            rule(Outbound::Proxy, &["domain:example.com"], &[]),
            rule(Outbound::Direct, &["domain:example.com"], &[]),
        ],
        ..RoutingConfig::default()
    };
    assert_eq!(
        router(c.clone()).evaluate("example.com", &[]).outbound,
        Outbound::Proxy
    );
    let mut swapped = c;
    swapped.rules.swap(0, 1);
    assert_eq!(
        router(swapped).evaluate("example.com", &[]).outbound,
        Outbound::Direct
    );
}

#[test]
fn domain_match_types_are_distinct_and_normalized() {
    let cases = [
        ("domain:example.com", "sub.example.com", true),
        ("domain:example.com", "badexample.com", false),
        ("full:example.com", "sub.example.com", false),
        ("full:example.com", "EXAMPLE.COM.", true),
        ("*.example.com", "example.com", false),
        ("*.example.com", "sub.example.com", true),
        ("example", "anotherexample.net", true),
        ("regexp:^bank[0-9]+\\.ir$", "bank12.ir", true),
        ("domain:ایران", "bank.xn--mgba3a4f16a", true),
    ];
    for (pattern, host, expected) in cases {
        let r = router(RoutingConfig {
            rules: vec![rule(Outbound::Direct, &[pattern], &[])],
            ..RoutingConfig::default()
        });
        assert_eq!(
            r.evaluate(host, &[]).outbound == Outbound::Direct,
            expected,
            "{pattern} vs {host}"
        );
    }
}

#[test]
fn geosite_and_ad_block_groups_load() {
    let r = router(RoutingConfig {
        rules: vec![rule(Outbound::Proxy, &["geosite:google"], &[])],
        default_outbound: Outbound::Direct,
        ..RoutingConfig::default()
    });
    assert_eq!(r.evaluate("www.google.com", &[]).outbound, Outbound::Proxy);
    let mut p = Profile::new("ads");
    p.routing = Some(RoutingConfig::default());
    let r = Router::for_profile(&p).unwrap();
    assert_eq!(r.evaluate("doubleclick.net", &[]).outbound, Outbound::Block);
}

#[test]
fn country_can_be_forced_to_proxy_and_inverse_rules_work() {
    let config = RoutingConfig {
        default_outbound: Outbound::Direct,
        rules: vec![rule(Outbound::Proxy, &[], &["geoip:ir"])],
        ..RoutingConfig::default()
    };
    let r = router(config);
    assert_eq!(r.evaluate("5.160.0.1", &[]).outbound, Outbound::Proxy);
    assert_eq!(r.evaluate("8.8.8.8", &[]).outbound, Outbound::Direct);
    let config = RoutingConfig {
        default_outbound: Outbound::Direct,
        rules: vec![rule(Outbound::Proxy, &[], &["geoip:!ir"])],
        ..RoutingConfig::default()
    };
    let r = router(config);
    assert_eq!(r.evaluate("5.160.0.1", &[]).outbound, Outbound::Direct);
    assert_eq!(r.evaluate("8.8.8.8", &[]).outbound, Outbound::Proxy);
}

#[test]
fn proxy_backup_preserves_pac_flags_and_reads_older_versions() {
    use rvpn_windows::sysproxy::ProxyBackup;
    let old: ProxyBackup =
        serde_json::from_str(r#"{"enable":0,"server":null,"override_list":null}"#).unwrap();
    assert_eq!(old.connection_flags, None);
    let current = ProxyBackup {
        connection_flags: Some(13),
        auto_config_url: Some("http://localhost/pac".into()),
        ..old
    };
    let copy: ProxyBackup =
        serde_json::from_str(&serde_json::to_string(&current).unwrap()).unwrap();
    assert_eq!(copy.connection_flags, Some(13));
    assert_eq!(copy.auto_config_url, current.auto_config_url);
}

#[tokio::test]
async fn socks4a_domain_routing_and_shutdown_close_active_flows() {
    let (dns, dns_task) = fake_dns([127, 0, 0, 1]).await;
    let (dest, echo_task) = echo().await;
    let r = Router::build(
        RoutingConfig {
            rules: vec![rule(Outbound::Direct, &["domain:direct.test"], &[])],
            ..RoutingConfig::default()
        },
        &BTreeMap::new(),
        &[dns],
    )
    .unwrap();
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = MixedProxy::start(
        "127.0.0.1:0".parse().unwrap(),
        backend.local_addr().unwrap(),
        r,
    )
    .await
    .unwrap();
    let addr = proxy.local_addr;
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut request = vec![4, 1];
    request.extend_from_slice(&dest.port().to_be_bytes());
    request.extend_from_slice(&[0, 0, 0, 1, 0]);
    request.extend_from_slice(b"direct.test\0");
    s.write_all(&request).await.unwrap();
    let mut reply = [0; 8];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 90);
    s.write_all(b"DATA").await.unwrap();
    let mut payload = [0; 4];
    s.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"DATA");
    drop(proxy);
    let mut b = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), s.read(&mut b))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(TcpStream::connect(addr).await.is_err());
    dns_task.abort();
    echo_task.abort();
}

#[test]
fn explicit_proxy_overrides_geoip_and_all_answers_are_considered() {
    let r = router(RoutingConfig {
        rules: vec![
            rule(Outbound::Proxy, &["domain:forced.ir"], &[]),
            rule(Outbound::Direct, &[], &["geoip:ir"]),
        ],
        ..RoutingConfig::default()
    });
    assert_eq!(
        r.evaluate("forced.ir", &ips(&["5.160.0.1"])).outbound,
        Outbound::Proxy
    );
    let route = r.evaluate("other.test", &ips(&["8.8.8.8", "5.160.0.1"]));
    assert_eq!(route.outbound, Outbound::Direct);
    assert_eq!(route.direct_ips, ips(&["5.160.0.1"]));
}

#[test]
fn invalid_rules_fail_instead_of_silent_proxy_fallback() {
    for bad in [
        rule(Outbound::Direct, &["domain:"], &[]),
        rule(Outbound::Direct, &["regexp:("], &[]),
        rule(Outbound::Direct, &[], &["not-an-ip"]),
        rule(Outbound::Direct, &[], &["geoip:nonexistent"]),
        rule(Outbound::Direct, &["geosite:nonexistent"], &[]),
        Rule::default(),
    ] {
        assert!(Router::build(
            RoutingConfig {
                rules: vec![bad],
                ..RoutingConfig::default()
            },
            &BTreeMap::new(),
            &[]
        )
        .is_err());
    }
}

#[test]
fn migration_serialization_disabled_rules_and_custom_database() {
    let mut p = Profile::new("legacy");
    p.split_tunnel_enabled = true;
    p.builtin_bypass_countries = vec!["IR".into()];
    p.bypass_domains = vec!["bank.com".into()];
    p.tunnel_domains = vec!["force.bank.com".into()];
    let c = RoutingConfig::from_profile(&p);
    let r = router(c.clone());
    assert_eq!(r.evaluate("bank.com", &[]).outbound, Outbound::Direct);
    assert_eq!(r.evaluate("force.bank.com", &[]).outbound, Outbound::Proxy);
    assert_eq!(r.evaluate("5.160.0.1", &[]).outbound, Outbound::Direct);
    p.routing = Some(c);
    let copy: Profile = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
    assert_eq!(p, copy);
    let mut c = RoutingConfig::iran_direct();
    c.rules[1].enabled = false;
    assert_eq!(
        router(c).evaluate("5.160.0.1", &[]).outbound,
        Outbound::Proxy
    );
    let custom = BTreeMap::from([("ir".into(), vec!["192.0.2.0/24".into()])]);
    let r = Router::build(RoutingConfig::iran_direct(), &custom, &[]).unwrap();
    assert_eq!(r.evaluate("192.0.2.1", &[]).outbound, Outbound::Direct);
    assert_eq!(r.evaluate("5.160.0.1", &[]).outbound, Outbound::Proxy);
}

#[test]
fn system_proxy_uses_http_connect_for_domain_preservation() {
    assert_eq!(
        rvpn_windows::sysproxy::proxy_server("127.0.0.1", 1080),
        "127.0.0.1:1080"
    );
}

async fn fake_dns(ip: [u8; 4]) -> (String, tokio::task::JoinHandle<()>) {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        let mut b = [0; 4096];
        while let Ok((n, peer)) = s.recv_from(&mut b).await {
            let query = &b[..n];
            if n < 16 {
                continue;
            }
            let a = query[n - 4..n - 2] == [0, 1];
            let mut out = query.to_vec();
            out[2] = 0x81;
            out[3] = 0x80;
            out[6] = 0;
            out[7] = if a { 1 } else { 0 };
            if a {
                out.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                out.extend_from_slice(&ip);
            }
            s.send_to(&out, peer).await.unwrap();
        }
    });
    (addr, task)
}

#[tokio::test]
async fn hostname_resolves_before_country_routing() {
    let (dns, task) = fake_dns([5, 160, 0, 1]).await;
    let r = Router::build(RoutingConfig::iran_direct(), &BTreeMap::new(), &[dns]).unwrap();
    let route = r.route("iranian-site.example").await.unwrap();
    assert_eq!(route.outbound, Outbound::Direct);
    assert_eq!(route.direct_ips, ips(&["5.160.0.1"]));
    task.abort();
}

async fn echo() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut b = [0; 1024];
                while let Ok(n) = s.read(&mut b).await {
                    if n == 0 {
                        break;
                    }
                    s.write_all(&b[..n]).await.unwrap();
                }
            });
        }
    });
    (addr, task)
}

#[tokio::test]
async fn http_connect_and_socks_dial_direct_and_reply_exactly_once() {
    let (dest, echo_task) = echo().await;
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = MixedProxy::start(
        "127.0.0.1:0".parse().unwrap(),
        backend.local_addr().unwrap(),
        router(RoutingConfig::iran_direct()),
    )
    .await
    .unwrap();
    for version in [0, 4, 5] {
        let mut s = TcpStream::connect(proxy.local_addr).await.unwrap();
        if version == 0 {
            s.write_all(format!("CONNECT {dest} HTTP/1.1\r\nHost: {dest}\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut response = vec![0; 39];
            s.read_exact(&mut response).await.unwrap();
            assert_eq!(response, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        } else if version == 4 {
            let mut request = vec![4, 1];
            request.extend_from_slice(&dest.port().to_be_bytes());
            request.extend_from_slice(&[127, 0, 0, 1, 0]);
            s.write_all(&request).await.unwrap();
            let mut response = [0; 8];
            s.read_exact(&mut response).await.unwrap();
            assert_eq!(response[1], 90);
        } else {
            s.write_all(&[5, 1, 0]).await.unwrap();
            let mut greeting = [0; 2];
            s.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 0]);
            let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
            request.extend_from_slice(&dest.port().to_be_bytes());
            s.write_all(&request).await.unwrap();
            let mut response = [0; 10];
            s.read_exact(&mut response).await.unwrap();
            assert_eq!(response[1], 0);
        }
        s.write_all(b"PAYLOAD").await.unwrap();
        let mut response = [0; 7];
        s.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"PAYLOAD");
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(40), backend.accept())
            .await
            .is_err(),
        "Direct must not reach rVPN backend"
    );
    drop(proxy);
    echo_task.abort();
}

#[tokio::test]
async fn http_domain_geoip_bypass_uses_same_resolved_ip_for_dialing() {
    let (dns, dns_task) = fake_dns([127, 0, 0, 1]).await;
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = origin.local_addr().unwrap().port();
    let origin_task = tokio::spawn(async move {
        let (mut s, _) = origin.accept().await.unwrap();
        let mut data = vec![0; 4096];
        let n = s.read(&mut data).await.unwrap();
        let header = String::from_utf8_lossy(&data[..n]);
        assert!(header.starts_with("GET /test?q=1 HTTP/1.1\r\n"));
        assert!(header.contains("Host: iran.test:"));
        assert!(!header.contains("Proxy-Authorization"));
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nDIRECT")
            .await
            .unwrap();
    });
    let custom = BTreeMap::from([("IR".into(), vec!["127.0.0.0/8".into()])]);
    let r = Router::build(
        RoutingConfig {
            rules: vec![rule(Outbound::Direct, &[], &["geoip:ir"])],
            ..RoutingConfig::default()
        },
        &custom,
        &[dns],
    )
    .unwrap();
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = MixedProxy::start(
        "127.0.0.1:0".parse().unwrap(),
        backend.local_addr().unwrap(),
        r,
    )
    .await
    .unwrap();
    let mut s = TcpStream::connect(proxy.local_addr).await.unwrap();
    s.write_all(format!("GET http://iran.test:{port}/test?q=1 HTTP/1.1\r\nHost: iran.test\r\nProxy-Authorization: secret-test-value\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = vec![];
    tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.ends_with(b"DIRECT"));
    origin_task.await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(40), backend.accept())
            .await
            .is_err()
    );
    dns_task.abort();
}

#[tokio::test]
async fn proxy_rule_preserves_original_domain_and_block_never_dials() {
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = backend.local_addr().unwrap();
    let (tx, mut rx) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        let (mut s, _) = backend.accept().await.unwrap();
        let mut greet = [0; 3];
        s.read_exact(&mut greet).await.unwrap();
        s.write_all(&[5, 0]).await.unwrap();
        let mut header = [0; 5];
        s.read_exact(&mut header).await.unwrap();
        assert_eq!(header[3], 3);
        let mut name = vec![0; header[4] as usize];
        s.read_exact(&mut name).await.unwrap();
        let port = s.read_u16().await.unwrap();
        tx.send((String::from_utf8(name).unwrap(), port))
            .await
            .unwrap();
        s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        let mut b = [0; 4];
        s.read_exact(&mut b).await.unwrap();
        s.write_all(&b).await.unwrap();
    });
    let config = RoutingConfig {
        rules: vec![rule(Outbound::Block, &["domain:blocked.test"], &[])],
        ..RoutingConfig::default()
    };
    let proxy = MixedProxy::start("127.0.0.1:0".parse().unwrap(), addr, router(config))
        .await
        .unwrap();
    let mut s = TcpStream::connect(proxy.local_addr).await.unwrap();
    s.write_all(b"CONNECT blocked.test:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut response = vec![];
    s.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 502"));
    let mut s = TcpStream::connect(proxy.local_addr).await.unwrap();
    s.write_all(b"CONNECT proxy.test:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut response = [0; 39];
    s.read_exact(&mut response).await.unwrap();
    s.write_all(b"TLS!").await.unwrap();
    let mut payload = [0; 4];
    s.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"TLS!");
    assert_eq!(rx.recv().await.unwrap(), ("proxy.test".into(), 443));
    task.await.unwrap();
}

// A DNS-over-SOCKS fixture speaks the same framed TCP DNS protocol as the
// tunneled resolver, but never touches the network outside loopback.
async fn tunneled_dns_backend(
    answer: [u8; 4],
    fail: bool,
) -> (
    std::net::SocketAddr,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    use hickory_proto::{
        op::{Message, MessageType},
        rr::{rdata::A, RData, Record, RecordType},
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let queries = Arc::new(AtomicUsize::new(0));
    let count = queries.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let count = count.clone();
            tokio::spawn(async move {
                let mut greeting = [0; 3];
                if s.read_exact(&mut greeting).await.is_err() {
                    return;
                }
                assert_eq!(greeting, [5, 1, 0]);
                s.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 10];
                if s.read_exact(&mut request).await.is_err() {
                    return;
                }
                assert_eq!(&request[..4], &[5, 1, 0, 1]);
                assert_eq!(&request[4..8], &[1, 1, 1, 1]);
                assert_eq!(u16::from_be_bytes([request[8], request[9]]), 53);
                s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                while let Ok(n) = s.read_u16().await {
                    let mut wire = vec![0; n as usize];
                    if s.read_exact(&mut wire).await.is_err() {
                        break;
                    }
                    count.fetch_add(1, Ordering::SeqCst);
                    if fail {
                        break;
                    }
                    let query = Message::from_vec(&wire).unwrap();
                    let q = query.queries()[0].clone();
                    let mut response = Message::new();
                    response
                        .set_id(query.id())
                        .set_message_type(MessageType::Response)
                        .add_query(q.clone());
                    if q.query_type() == RecordType::A {
                        response.add_answer(Record::from_rdata(
                            q.name().clone(),
                            60,
                            RData::A(A(answer.into())),
                        ));
                    }
                    let wire = response.to_vec().unwrap();
                    if s.write_u16(wire.len() as u16).await.is_err()
                        || s.write_all(&wire).await.is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    (addr, queries, task)
}

#[tokio::test]
async fn poisoned_local_facebook_dns_cannot_trigger_private_bypass() {
    use std::sync::atomic::Ordering;
    let (poison, local) = fake_dns([10, 10, 34, 36]).await;
    // Verify the local-only configuration reproduces the reported failure.
    let r = Router::build(
        RoutingConfig::iran_direct(),
        &BTreeMap::new(),
        &[poison.clone()],
    )
    .unwrap();
    assert_eq!(
        r.route("www.facebook.com").await.unwrap().outbound,
        Outbound::Direct
    );
    let (backend, count, task) = tunneled_dns_backend([157, 240, 1, 35], false).await;
    let r = Router::build(RoutingConfig::iran_direct(), &BTreeMap::new(), &[poison])
        .unwrap()
        .with_tunnel_dns(backend, &["1.1.1.1".into()])
        .unwrap();
    // Concurrent browser requests share one A+AAAA lookup.
    let (first, second) = tokio::join!(r.route("www.facebook.com"), r.route("www.facebook.com"));
    assert_eq!(first.unwrap().outbound, Outbound::Proxy);
    assert_eq!(second.unwrap().outbound, Outbound::Proxy);
    assert_eq!(
        r.route("www.facebook.com").await.unwrap().outbound,
        Outbound::Proxy
    );
    assert_eq!(
        count.load(Ordering::SeqCst),
        2,
        "DNS cache must coalesce repeated browser requests"
    );
    local.abort();
    task.abort();
}

#[tokio::test]
async fn tunneled_geoip_lookup_still_bypasses_real_iranian_addresses() {
    let (backend, _, task) = tunneled_dns_backend([5, 160, 0, 1], false).await;
    let r = router(RoutingConfig::iran_direct())
        .with_tunnel_dns(backend, &["1.1.1.1".into()])
        .unwrap();
    let route = r.route("domestic-site.example").await.unwrap();
    assert_eq!(route.outbound, Outbound::Direct);
    assert_eq!(route.direct_ips, ips(&["5.160.0.1"]));
    task.abort();
}

#[tokio::test]
async fn tunnel_dns_failure_never_falls_back_to_poisoned_local_dns() {
    let (poison, local) = fake_dns([10, 10, 34, 36]).await;
    let (backend, _, task) = tunneled_dns_backend([157, 240, 1, 35], true).await;
    let r = Router::build(RoutingConfig::iran_direct(), &BTreeMap::new(), &[poison])
        .unwrap()
        .with_tunnel_dns(backend, &["1.1.1.1".into()])
        .unwrap();
    assert!(r.route("www.facebook.com").await.is_err());
    // Explicit direct domains remain independent of tunnel DNS.
    assert_eq!(r.route("bank.ir").await.unwrap().outbound, Outbound::Direct);
    local.abort();
    task.abort();
}
