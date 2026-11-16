//! Routing DNS travels over the encrypted proxy path, independently of the
//! direct resolver. Reuse a small pool of DNS-over-TCP streams to avoid an
//! X3DH handshake for every browser lookup. Never fall back to the local DNS.
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

static QUERY_ID: AtomicU16 = AtomicU16::new(1);
struct Connection {
    server: SocketAddr,
    stream: Mutex<Option<TcpStream>>,
}
struct Cached {
    until: Instant,
    result: std::result::Result<Vec<IpAddr>, String>,
}
type HostCache = Arc<Mutex<Option<Cached>>>;

pub struct TunnelDns {
    backend: SocketAddr,
    pool: Vec<Connection>,
    next: AtomicUsize,
    cache: Mutex<HashMap<String, HostCache>>,
}

impl TunnelDns {
    pub fn new(backend: SocketAddr, servers: &[String]) -> Result<Self> {
        anyhow::ensure!(
            backend.ip().is_loopback(),
            "Routing DNS backend must be loopback"
        );
        let servers = if servers.is_empty() {
            vec!["1.1.1.1".into()]
        } else {
            servers.to_vec()
        };
        let servers: Vec<SocketAddr> = servers
            .iter()
            .map(|s| {
                s.parse::<SocketAddr>()
                    .or_else(|_| s.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
            })
            .collect::<std::result::Result<_, _>>()
            .context("Invalid tunnel DNS resolver")?;
        anyhow::ensure!(
            servers.iter().all(|s| s.port() != 0),
            "Tunnel DNS port must be nonzero"
        );
        let pool = (0..4)
            .map(|i| Connection {
                server: servers[i % servers.len()],
                stream: Mutex::new(None),
            })
            .collect();
        Ok(Self {
            backend,
            pool,
            next: AtomicUsize::new(0),
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        let entry = {
            let mut cache = self.cache.lock().await;
            if cache.len() >= 4096 && !cache.contains_key(host) {
                cache.clear();
            }
            cache
                .entry(host.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(None)))
                .clone()
        };
        // Holding this per-host lock coalesces simultaneous Chrome requests.
        let mut cached = entry.lock().await;
        if let Some(value) = cached.as_ref().filter(|v| v.until > Instant::now()) {
            return value.result.clone().map_err(anyhow::Error::msg);
        }
        let (v4, v6) = tokio::join!(
            self.query(host, RecordType::A),
            self.query(host, RecordType::AAAA)
        );
        let mut ips = vec![];
        let mut ttl = 300;
        let mut errors = vec![];
        for response in [v4, v6] {
            match response {
                Ok((addresses, seconds)) => {
                    ips.extend(addresses);
                    ttl = ttl.min(seconds);
                }
                Err(error) => errors.push(format!("{error:#}")),
            }
        }
        ips.sort();
        ips.dedup();
        // Prefer IPv4 for direct dialing but retain IPv6 for GeoIP matching.
        ips.sort_by_key(|ip| !ip.is_ipv4());
        let result = if ips.is_empty() {
            Err(format!(
                "Tunnel DNS returned no addresses for {host}: {}",
                errors.join("; ")
            ))
        } else {
            Ok(ips)
        };
        let seconds = if result.is_ok() { ttl.clamp(1, 300) } else { 5 };
        *cached = Some(Cached {
            until: Instant::now() + Duration::from_secs(seconds as u64),
            result: result.clone(),
        });
        result.map_err(anyhow::Error::msg)
    }

    async fn query(&self, host: &str, kind: RecordType) -> Result<(Vec<IpAddr>, u32)> {
        let mut query = Message::new();
        query
            .set_id(QUERY_ID.fetch_add(1, Ordering::Relaxed))
            .set_recursion_desired(true)
            .add_query(Query::query(Name::from_ascii(host)?, kind));
        let wire = query.to_vec()?;
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        let mut last_error = None;
        for attempt in 0..2 {
            let connection = &self.pool[(start + attempt) % self.pool.len()];
            let exchange = async {
                let mut slot = connection.stream.lock().await;
                // Own the checked-out stream while awaiting I/O. If a caller
                // cancels resolution, a partially read stream is closed rather
                // than returned to the pool with a stale DNS response pending.
                let mut checked_out = slot.take();
                let result = tokio::time::timeout(Duration::from_secs(5), async {
                    if checked_out.is_none() {
                        checked_out = Some(
                            crate::proxy::connect_backend(
                                self.backend,
                                &connection.server.ip().to_string(),
                                connection.server.port(),
                            )
                            .await?,
                        );
                    }
                    let stream = checked_out.as_mut().unwrap();
                    stream.write_u16(u16::try_from(wire.len())?).await?;
                    stream.write_all(&wire).await?;
                    let length = stream.read_u16().await? as usize;
                    anyhow::ensure!(length >= 12, "Short tunnel DNS response");
                    let mut response = vec![0; length];
                    stream.read_exact(&mut response).await?;
                    parse_response(&response, query.id(), host, kind)
                })
                .await
                .context("Tunnel DNS exchange timed out")
                .and_then(|r| r);
                if result.is_ok() {
                    *slot = checked_out;
                }
                result
            };
            match exchange.await {
                Ok(answer) => return Ok(answer),
                Err(error) => last_error = Some(error),
            }
            // Transient link resets (RST bursts) kill back-to-back attempts
            // on separate connections just as easily; give the path a beat
            // to recover before the next try.
            tokio::time::sleep(Duration::from_millis(350)).await;
        }
        Err(last_error.unwrap()).context("DNS over the rVPN tunnel failed")
    }
}

fn parse_response(
    wire: &[u8],
    id: u16,
    host: &str,
    kind: RecordType,
) -> Result<(Vec<IpAddr>, u32)> {
    let response = Message::from_vec(wire)?;
    anyhow::ensure!(
        response.id() == id
            && response.message_type() == MessageType::Response
            && !response.truncated(),
        "Invalid tunnel DNS response header"
    );
    anyhow::ensure!(
        response.queries().len() == 1
            && response.queries()[0].query_type() == kind
            && response.queries()[0]
                .name()
                .to_ascii()
                .trim_end_matches('.')
                .eq_ignore_ascii_case(host.trim_end_matches('.')),
        "Tunnel DNS question mismatch"
    );
    if response.response_code() != ResponseCode::NoError {
        bail!("Tunnel DNS error: {}", response.response_code());
    }
    let mut ips = vec![];
    let mut ttl = 300;
    for record in response.answers() {
        let ip = match record.data() {
            Some(RData::A(ip)) if kind == RecordType::A => Some(IpAddr::V4(ip.0)),
            Some(RData::AAAA(ip)) if kind == RecordType::AAAA => Some(IpAddr::V6(ip.0)),
            _ => None,
        };
        if let Some(ip) = ip {
            ips.push(ip);
            ttl = ttl.min(record.ttl());
        }
    }
    Ok((ips, ttl))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{
        rdata::{A, AAAA},
        Record,
    };

    fn response(kind: RecordType) -> Message {
        let mut message = Message::new();
        message
            .set_id(123)
            .set_message_type(MessageType::Response)
            .add_query(Query::query(
                Name::from_ascii("www.facebook.com").unwrap(),
                kind,
            ));
        message
    }

    #[test]
    fn unrelated_or_truncated_dns_responses_are_rejected() {
        let mut message = response(RecordType::A);
        assert!(parse_response(
            &message.to_vec().unwrap(),
            124,
            "www.facebook.com",
            RecordType::A
        )
        .is_err());
        assert!(parse_response(
            &message.to_vec().unwrap(),
            123,
            "other.example",
            RecordType::A
        )
        .is_err());
        message.set_truncated(true);
        assert!(parse_response(
            &message.to_vec().unwrap(),
            123,
            "www.facebook.com",
            RecordType::A
        )
        .is_err());
        message
            .set_truncated(false)
            .set_response_code(ResponseCode::NXDomain);
        assert!(parse_response(
            &message.to_vec().unwrap(),
            123,
            "www.facebook.com",
            RecordType::A
        )
        .is_err());
    }

    #[test]
    fn ipv4_and_ipv6_answers_keep_dns_ttl() {
        let host = Name::from_ascii("www.facebook.com").unwrap();
        let mut v4 = response(RecordType::A);
        v4.add_answer(Record::from_rdata(
            host.clone(),
            42,
            RData::A(A([157, 240, 1, 35].into())),
        ));
        let (ips, ttl) = parse_response(
            &v4.to_vec().unwrap(),
            123,
            "www.facebook.com",
            RecordType::A,
        )
        .unwrap();
        assert_eq!(ips, vec!["157.240.1.35".parse::<IpAddr>().unwrap()]);
        assert_eq!(ttl, 42);
        let mut v6 = response(RecordType::AAAA);
        let addr = "2a03:2880::1".parse::<std::net::Ipv6Addr>().unwrap();
        v6.add_answer(Record::from_rdata(host, 24, RData::AAAA(AAAA(addr))));
        let (ips, ttl) = parse_response(
            &v6.to_vec().unwrap(),
            123,
            "www.facebook.com",
            RecordType::AAAA,
        )
        .unwrap();
        assert_eq!(ips, vec![IpAddr::V6(addr)]);
        assert_eq!(ttl, 24);
    }
}
