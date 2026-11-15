//! Mixed HTTP/SOCKS local inbound. Windows uses HTTP (as v2rayN does), so
//! HTTPS CONNECT preserves the hostname for routing rather than losing it
//! in WinINET's locally-resolved SOCKS4 request. Proxy outbounds are handed
//! to the existing rVPN SOCKS engine on an ephemeral, loopback-only port.
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

use crate::routing::{Outbound, Router};

pub struct MixedProxy {
    pub local_addr: SocketAddr,
    task: JoinHandle<()>,
}
impl Drop for MixedProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MixedProxy {
    pub async fn start(listen: SocketAddr, backend: SocketAddr, router: Router) -> Result<Self> {
        anyhow::ensure!(
            listen.ip().is_loopback() && backend.ip().is_loopback(),
            "Proxy must bind to loopback"
        );
        let listener = TcpListener::bind(listen)
            .await
            .context("Cannot bind local HTTP/SOCKS proxy")?;
        let local_addr = listener.local_addr()?;
        let router = Arc::new(router);
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((socket,_)) = accepted else { break };
                        let router = router.clone();
                        connections.spawn(async move {
                            if let Err(e) = serve(socket,backend,router).await {
                                tracing::debug!(error = %format!("{e:#}"), "local proxy connection ended");
                            }
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        Ok(Self { local_addr, task })
    }
}

#[derive(Clone, Copy)]
enum Protocol {
    HttpConnect,
    HttpForward,
    Socks4,
    Socks5,
}
struct Request {
    protocol: Protocol,
    host: String,
    port: u16,
    initial: Vec<u8>,
}

async fn serve(mut client: TcpStream, backend: SocketAddr, router: Arc<Router>) -> Result<()> {
    let request =
        tokio::time::timeout(Duration::from_secs(15), read_request(&mut client)).await??;
    let outbound = async {
        let route = router.route(&request.host).await?;
        tracing::info!(host = %request.host, port = request.port, outbound = ?route.outbound, rule = %route.rule, "routing connection");
        match route.outbound {
            Outbound::Block => bail!("Blocked by {}", route.rule),
            Outbound::Direct => {
                let addrs = router
                    .direct_addresses(&request.host, request.port, &route)
                    .await?;
                let mut last_error = None;
                for addr in addrs {
                    match tokio::time::timeout(Duration::from_secs(4), TcpStream::connect(addr))
                        .await
                    {
                        Ok(Ok(socket)) => return Ok(socket),
                        Ok(Err(e)) => last_error = Some(e.to_string()),
                        Err(_) => last_error = Some("connect timeout".into()),
                    }
                }
                bail!(
                    "Direct connection failed: {}",
                    last_error.unwrap_or_else(|| "no addresses".into())
                )
            }
            Outbound::Proxy => connect_backend(backend, &request.host, request.port).await,
        }
    };
    let mut remote = match tokio::time::timeout(Duration::from_secs(25), outbound).await {
        Ok(Ok(socket)) => socket,
        result => {
            if let Ok(Err(error)) = &result {
                if !error.to_string().starts_with("Blocked by ") {
                    tracing::warn!(host = %request.host, port = request.port, error = %format!("{error:#}"), "proxy outbound failed");
                }
            }
            reply(&mut client, request.protocol, false).await?;
            return match result {
                Ok(Err(e)) => Err(e),
                _ => Err(anyhow::anyhow!("Outbound connection timed out")),
            };
        }
    };
    reply(&mut client, request.protocol, true).await?;
    if !request.initial.is_empty() {
        remote.write_all(&request.initial).await?;
    }
    tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
    Ok(())
}

async fn read_request(socket: &mut TcpStream) -> Result<Request> {
    let mut first = [0];
    anyhow::ensure!(socket.peek(&mut first).await? == 1, "Empty request");
    match first[0] {
        4 => read_socks4(socket).await,
        5 => read_socks5(socket).await,
        _ => read_http(socket).await,
    }
}

async fn read_socks5(socket: &mut TcpStream) -> Result<Request> {
    let mut greeting = [0; 2];
    socket.read_exact(&mut greeting).await?;
    let mut methods = vec![0; greeting[1] as usize];
    socket.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        socket.write_all(&[5, 255]).await?;
        bail!("SOCKS authentication unsupported");
    }
    socket.write_all(&[5, 0]).await?;
    let mut header = [0; 4];
    socket.read_exact(&mut header).await?;
    if header[0] != 5 || header[1] != 1 || header[2] != 0 {
        socket.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        bail!("Only SOCKS CONNECT is supported");
    }
    let host = match header[3] {
        1 => {
            let mut b = [0; 4];
            socket.read_exact(&mut b).await?;
            std::net::Ipv4Addr::from(b).to_string()
        }
        4 => {
            let mut b = [0; 16];
            socket.read_exact(&mut b).await?;
            std::net::Ipv6Addr::from(b).to_string()
        }
        3 => {
            let n = socket.read_u8().await?;
            let mut b = vec![0; n as usize];
            socket.read_exact(&mut b).await?;
            String::from_utf8(b)?
        }
        _ => {
            reply(socket, Protocol::Socks5, false).await?;
            bail!("Unknown SOCKS address type");
        }
    };
    let port = socket.read_u16().await?;
    validate_host(&host, port)?;
    Ok(Request {
        protocol: Protocol::Socks5,
        host,
        port,
        initial: vec![],
    })
}

async fn read_socks4(socket: &mut TcpStream) -> Result<Request> {
    let mut header = [0; 8];
    socket.read_exact(&mut header).await?;
    if header[1] != 1 {
        reply(socket, Protocol::Socks4, false).await?;
        bail!("Only SOCKS4 CONNECT supported");
    }
    let port = u16::from_be_bytes([header[2], header[3]]);
    read_cstring(socket, 1024).await?; // USERID
    let host = if header[4..7] == [0, 0, 0] && header[7] != 0 {
        String::from_utf8(read_cstring(socket, 255).await?)?
    } else {
        std::net::Ipv4Addr::new(header[4], header[5], header[6], header[7]).to_string()
    };
    validate_host(&host, port)?;
    Ok(Request {
        protocol: Protocol::Socks4,
        host,
        port,
        initial: vec![],
    })
}
async fn read_cstring(socket: &mut TcpStream, limit: usize) -> Result<Vec<u8>> {
    let mut value = vec![];
    for _ in 0..=limit {
        let b = socket.read_u8().await?;
        if b == 0 {
            return Ok(value);
        }
        value.push(b);
    }
    bail!("SOCKS field too long")
}

async fn read_http(socket: &mut TcpStream) -> Result<Request> {
    let mut data = vec![];
    let header_end = loop {
        if let Some(pos) = data.windows(4).position(|v| v == b"\r\n\r\n") {
            anyhow::ensure!(pos + 4 <= 32768, "HTTP proxy header exceeds 32 KiB");
            break pos + 4;
        }
        if data.len() >= 32768 {
            bail!("HTTP proxy header exceeds 32 KiB");
        }
        let mut buf = [0; 2048];
        let n = socket.read(&mut buf).await?;
        anyhow::ensure!(n > 0, "Incomplete HTTP proxy request");
        data.extend_from_slice(&buf[..n]);
    };
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut parsed = httparse::Request::new(&mut headers);
    anyhow::ensure!(
        parsed.parse(&data[..header_end])?.is_complete(),
        "Incomplete HTTP request"
    );
    let method = parsed.method.context("Missing HTTP method")?;
    let target = parsed.path.context("Missing request target")?;
    if method == "CONNECT" {
        let (host, port) = authority(target, 443)?;
        return Ok(Request {
            protocol: Protocol::HttpConnect,
            host,
            port,
            initial: data[header_end..].to_vec(),
        });
    }
    let url = url::Url::parse(target).context("HTTP proxy requires an absolute http:// URL")?;
    anyhow::ensure!(
        url.scheme() == "http" && url.username().is_empty() && url.password().is_none(),
        "Unsupported HTTP proxy URL"
    );
    let host = url
        .host_str()
        .context("HTTP URL has no host")?
        .trim_matches(['[', ']'])
        .to_string();
    let port = url
        .port_or_known_default()
        .context("HTTP URL has no port")?;
    validate_host(&host, port)?;
    let path = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };
    let mut initial = format!("{method} {path} HTTP/1.1\r\n").into_bytes();
    let upgrade = parsed
        .headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("upgrade"));
    // One origin per proxy connection: don't allow a second keepalive request
    // for a different host to reuse the first host's routing decision.
    for h in parsed.headers.iter() {
        if [
            "proxy-connection",
            "proxy-authorization",
            "connection",
            "host",
        ]
        .iter()
        .any(|v| h.name.eq_ignore_ascii_case(v))
        {
            continue;
        }
        initial.extend_from_slice(h.name.as_bytes());
        initial.extend_from_slice(b": ");
        initial.extend_from_slice(h.value);
        initial.extend_from_slice(b"\r\n");
    }
    initial.extend_from_slice(
        format!(
            "Host: {}\r\nConnection: {}\r\n\r\n",
            &url[url::Position::BeforeHost..url::Position::AfterPort],
            if upgrade { "Upgrade" } else { "close" }
        )
        .as_bytes(),
    );
    initial.extend_from_slice(&data[header_end..]);
    Ok(Request {
        protocol: Protocol::HttpForward,
        host,
        port,
        initial,
    })
}

fn authority(value: &str, default_port: u16) -> Result<(String, u16)> {
    let url = url::Url::parse(&format!("http://{value}"))?;
    anyhow::ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none(),
        "Invalid CONNECT authority"
    );
    let host = url
        .host_str()
        .context("Missing CONNECT host")?
        .trim_matches(['[', ']'])
        .to_string();
    let port = url.port().unwrap_or(default_port);
    validate_host(&host, port)?;
    Ok((host, port))
}
fn validate_host(host: &str, port: u16) -> Result<()> {
    anyhow::ensure!(
        !host.is_empty()
            && host.len() <= 253
            && port != 0
            && !host.bytes().any(|b| b <= 32 || b == 127),
        "Invalid proxy target"
    );
    Ok(())
}

async fn reply(socket: &mut TcpStream, protocol: Protocol, success: bool) -> Result<()> {
    match protocol {
        Protocol::Socks4 => {
            socket
                .write_all(&[0, if success { 90 } else { 91 }, 0, 0, 0, 0, 0, 0])
                .await?
        }
        Protocol::Socks5 => {
            socket
                .write_all(&[5, if success { 0 } else { 2 }, 0, 1, 0, 0, 0, 0, 0, 0])
                .await?
        }
        Protocol::HttpConnect if success => {
            socket
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?
        }
        Protocol::HttpForward if success => {}
        _ => {
            socket
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                )
                .await?
        }
    }
    Ok(())
}

/// No system proxy lookup is involved: connect directly to the loopback rVPN engine.
pub(crate) async fn connect_backend(
    backend: SocketAddr,
    host: &str,
    port: u16,
) -> Result<TcpStream> {
    let mut socket = TcpStream::connect(backend).await?;
    socket.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    socket.read_exact(&mut greeting).await?;
    anyhow::ensure!(greeting == [5, 0], "rVPN SOCKS negotiation failed");
    let mut request = vec![5, 1, 0];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(4);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            anyhow::ensure!(host.len() <= 255, "Hostname too long");
            request.extend_from_slice(&[3, host.len() as u8]);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    socket.write_all(&request).await?;
    let mut response = [0; 4];
    socket.read_exact(&mut response).await?;
    anyhow::ensure!(
        response[0] == 5 && response[1] == 0,
        "rVPN CONNECT rejected"
    );
    let size = match response[3] {
        1 => 4,
        4 => 16,
        3 => socket.read_u8().await? as usize,
        _ => bail!("Invalid rVPN SOCKS reply"),
    };
    let mut bound = vec![0; size + 2];
    socket.read_exact(&mut bound).await?;
    Ok(socket)
}
