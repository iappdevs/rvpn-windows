//! Exercise the new routing frontend against an already-running rVPN SOCKS
//! backend. Reads no saved profiles or identities; never sets system proxy.
//! Usage: --backend-port N --output D:/probe [--chrome C:/.../chrome.exe]
use anyhow::{Context, Result};
use rvpn_windows::{
    profile::{ConnMode, Profile},
    proxy::MixedProxy,
    routing::{Router, RoutingConfig},
};
use std::{
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let value = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let backend_port: u16 = value("--backend-port")
        .context("--backend-port is required")?
        .parse()?;
    let output = PathBuf::from(value("--output").context("--output is required")?);
    std::fs::create_dir_all(&output)?;
    let backend = format!("127.0.0.1:{backend_port}").parse()?;
    let mut profile = Profile::new("Read-only proxy probe");
    profile.mode = ConnMode::Proxy;
    profile.routing = Some(RoutingConfig::iran_direct());
    profile.block_ads = true;
    let router = Router::for_profile(&profile)?.with_tunnel_dns(backend, &profile.dns_servers)?;
    for host in ["www.facebook.com", "www.aparat.com"] {
        match router.route(host).await {
            Ok(route) => println!(
                "ROUTE {host}: {:?}, rule={}, resolved={:?}",
                route.outbound, route.rule, route.direct_ips
            ),
            Err(error) => println!("ROUTE {host}: ERROR {error:#}"),
        }
    }
    let proxy = MixedProxy::start("127.0.0.1:0".parse()?, backend, router).await?;
    let proxy_url = format!("http://{}", proxy.local_addr);
    println!("PROBE_PROXY={proxy_url}");
    let curl_proxy = proxy_url.clone();
    tokio::task::spawn_blocking(move ||->Result<()> {
        for url in ["https://www.facebook.com/","https://example.com/"] {
            let result=Command::new("curl.exe").args(["--proxy",&curl_proxy,"--noproxy","","--max-time","20","--silent","--show-error","--output","NUL","--write-out","http=%{http_code} connect=%{http_connect} bytes=%{size_download} exit=%{exitcode}",url]).output()?;
            println!("CURL {url}: {}",String::from_utf8_lossy(&result.stdout));
            anyhow::ensure!(result.status.success(),"curl failed for {url}: {}",String::from_utf8_lossy(&result.stderr));
        }
        Ok(())
    }).await??;
    if let Some(chrome) = value("--chrome") {
        tokio::task::spawn_blocking(move ||->Result<()> {
            let profile_dir=tempfile::Builder::new().prefix("chrome-proxy-probe-").tempdir_in(&output)?;
            let html=output.join("facebook-chrome.html");let screenshot=output.join("facebook-chrome.png");
            let mut child=Command::new(chrome).args(["--headless=new","--no-first-run","--no-default-browser-check","--disable-extensions","--disable-background-networking","--disable-sync","--timeout=20000","--virtual-time-budget=5000","--window-size=1280,900","--hide-scrollbars","--dump-dom"])
                .arg(format!("--user-data-dir={}",profile_dir.path().display()))
                .arg(format!("--proxy-server={proxy_url}"))
                .arg(format!("--screenshot={}",screenshot.display()))
                .arg("https://www.facebook.com/")
                .stdout(Stdio::from(std::fs::File::create(&html)?))
                .stderr(Stdio::from(std::fs::File::create(output.join("chrome-stderr.log"))?)).spawn()?;
            let deadline=Instant::now()+Duration::from_secs(35);
            let status=loop {
                if let Some(status)=child.try_wait()? {break status;}
                if Instant::now()>=deadline {let _=child.kill();let _=child.wait();anyhow::bail!("Chrome probe timed out");}
                std::thread::sleep(Duration::from_millis(100));
            };
            let dom=std::fs::read_to_string(&html)?;
            let title=dom.split("<title>").nth(1).and_then(|s|s.split("</title>").next()).unwrap_or("(no title)");
            let error_page=dom.contains("chrome-error://chromewebdata") || dom.contains("id=\"main-frame-error\"");
            println!("CHROME status={status} title={title} error_page={error_page} html_bytes={} screenshot={}",dom.len(),screenshot.display());
            anyhow::ensure!(status.success() && !error_page && title.to_ascii_lowercase().contains("facebook"),"Chrome did not load a Facebook page");
            Ok(())
        }).await??;
    }
    drop(proxy);
    Ok(())
}
