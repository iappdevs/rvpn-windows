//! Verified, persistent GeoIP/GeoSite generations. The pair is published by
//! replacing one small pointer only after both files pass hashes and decoding.
//! Downloads use an internal SOCKS tunnel before Windows system proxy is set.
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::{header, Client, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::routing::{self, GeoData};

const REPOSITORY: &str = "Loyalsoldier/v2ray-rules-dat";
const BUNDLED_VERSION: &str = "202611132203 (bundled)";
const MAX_DATABASE: usize = 64 * 1024 * 1024;
const MAX_METADATA: usize = 2 * 1024 * 1024;
static GENERATION: AtomicU64 = AtomicU64::new(0);

pub fn generation() -> u64 {
    GENERATION.load(Ordering::Acquire)
}

#[derive(Debug, Clone)]
pub struct UpdateReport {
    pub version: String,
    pub updated: bool,
    pub warning: Option<String>,
}
impl UpdateReport {
    pub fn description(&self) -> String {
        format!(
            "{} · {}",
            self.version,
            if self.warning.is_some() {
                "update unavailable; using saved data"
            } else if self.updated {
                "updated"
            } else {
                "checked; up to date"
            }
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct Asset {
    name: String,
    id: u64,
    size: u64,
    updated_at: String,
    #[serde(default)]
    digest: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Release {
    id: u64,
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    assets: Vec<Asset>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Manifest {
    version: String,
    release_id: u64,
    geoip: Asset,
    geosite: Asset,
    geoip_sha256: String,
    geosite_sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct Pointer {
    directory: String,
    etag: Option<String>,
}
#[derive(Clone)]
struct Snapshot {
    manifest: Manifest,
    pointer: Pointer,
    data: Arc<GeoData>,
}
struct Outcome {
    snapshot: Snapshot,
    updated: bool,
}

struct Source {
    latest: String,
    downloads: String,
}
impl Source {
    fn github() -> Self {
        Self {
            latest: format!("https://api.github.com/repos/{REPOSITORY}/releases/latest"),
            downloads: format!("https://github.com/{REPOSITORY}/releases/download"),
        }
    }
    fn asset(&self, tag: &str, name: &str) -> String {
        format!("{}/{tag}/{name}", self.downloads)
    }
}

fn client(backend: Option<SocketAddr>) -> Result<Client> {
    let mut builder = Client::builder()
        .no_proxy()
        .user_agent(concat!("rvpn-windows/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(45))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            let allowed = matches!(
                attempt.url().host_str(),
                Some(
                    "github.com"
                        | "api.github.com"
                        | "release-assets.githubusercontent.com"
                        | "objects.githubusercontent.com"
                )
            );
            if attempt.previous().len() >= 5 || attempt.url().scheme() != "https" || !allowed {
                attempt.error("Unexpected geodata download redirect")
            } else {
                attempt.follow()
            }
        }));
    if let Some(addr) = backend {
        anyhow::ensure!(addr.ip().is_loopback(), "Geodata backend must be loopback");
        builder = builder.proxy(reqwest::Proxy::all(format!("socks5h://{addr}"))?);
    }
    Ok(builder.build()?)
}

/// Runs on the connect worker before Set Proxy. Failures preserve the last
/// verified cache (or bundled fallback) and are visible to the user.
pub async fn refresh_before_proxy(
    backend: SocketAddr,
    progress: impl FnMut(String),
) -> UpdateReport {
    update_cache(&crate::paths::geodata_dir(), Some(backend), progress).await
}

/// Also used by the standalone updater diagnostic; does not touch Windows proxy.
pub async fn update_cache(
    root: &Path,
    backend: Option<SocketAddr>,
    mut progress: impl FnMut(String),
) -> UpdateReport {
    let work = async {
        let client = client(backend)?;
        refresh(root, &Source::github(), &client, &mut progress).await
    };
    let result = tokio::time::timeout(Duration::from_secs(120), work)
        .await
        .context("Geodata update exceeded two minutes")
        .and_then(|r| r);
    match result {
        Ok(outcome) => {
            let version = outcome.snapshot.manifest.version.clone();
            routing::activate_geodata(outcome.snapshot.data);
            GENERATION.fetch_add(1, Ordering::Release);
            tracing::info!(
                version,
                updated = outcome.updated,
                "GeoIP/GeoSite verified before system proxy"
            );
            UpdateReport {
                version,
                updated: outcome.updated,
                warning: None,
            }
        }
        Err(error) => {
            let warning = format!("{error:#}");
            tracing::warn!(error=%warning,"GeoIP/GeoSite update unavailable; retaining verified data");
            let (version, data) = match load(root) {
                Ok(Some(snapshot)) => (snapshot.manifest.version, snapshot.data),
                _ => (
                    BUNDLED_VERSION.into(),
                    routing::bundled_geodata()
                        .expect("bundled geodata is validated by release tests"),
                ),
            };
            routing::activate_geodata(data);
            GENERATION.fetch_add(1, Ordering::Release);
            UpdateReport {
                version,
                updated: false,
                warning: Some(warning),
            }
        }
    }
}

pub(crate) fn load_cached_data() -> Result<Option<Arc<GeoData>>> {
    Ok(load(&crate::paths::geodata_dir())?.map(|snapshot| snapshot.data))
}

fn load(root: &Path) -> Result<Option<Snapshot>> {
    let pointer_file = root.join("current.json");
    if !pointer_file.is_file() {
        return Ok(None);
    }
    let pointer: Pointer = serde_json::from_slice(&read_bounded(&pointer_file, 4096)?)?;
    anyhow::ensure!(
        pointer.directory.starts_with("release-") && safe_component(&pointer.directory),
        "Invalid geodata cache pointer"
    );
    let dir = root.join("releases").join(&pointer.directory);
    let manifest: Manifest =
        serde_json::from_slice(&read_bounded(&dir.join("manifest.json"), 32768)?)?;
    let ips = read_bounded(&dir.join("geoip.dat"), MAX_DATABASE)?;
    let sites = read_bounded(&dir.join("geosite.dat"), MAX_DATABASE)?;
    verify(&ips, &manifest.geoip_sha256, "cached GeoIP")?;
    verify(&sites, &manifest.geosite_sha256, "cached GeoSite")?;
    let data = routing::decode_geodata(&ips, &sites)?;
    Ok(Some(Snapshot {
        manifest,
        pointer,
        data,
    }))
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let file = fs::File::open(path)?;
    anyhow::ensure!(
        file.metadata()?.len() <= limit as u64,
        "Oversized geodata cache file"
    );
    let mut bytes = vec![];
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= limit, "Oversized geodata cache file");
    Ok(bytes)
}
fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 180
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn verify(bytes: &[u8], expected: &str, name: &str) -> Result<()> {
    anyhow::ensure!(
        expected.len() == 64
            && expected.bytes().all(|b| b.is_ascii_hexdigit())
            && sha256(bytes).eq_ignore_ascii_case(expected),
        "SHA-256 mismatch for {name}"
    );
    Ok(())
}
fn checksum(bytes: &[u8], file: &str) -> Result<String> {
    let text = std::str::from_utf8(bytes)?;
    let fields: Vec<_> = text.split_whitespace().collect();
    anyhow::ensure!(
        !fields.is_empty()
            && fields.len() <= 2
            && fields[0].len() == 64
            && fields[0].bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid checksum for {file}"
    );
    if fields.len() == 2 {
        anyhow::ensure!(
            fields[1].trim_start_matches('*') == file,
            "Checksum filename mismatch"
        );
    }
    Ok(fields[0].to_ascii_lowercase())
}

async fn response_bytes(response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    let response = response.error_for_status().map_err(|e| e.without_url())?;
    anyhow::ensure!(
        response.content_length().unwrap_or(0) <= limit as u64,
        "Geodata response exceeds size limit"
    );
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.without_url())? {
        anyhow::ensure!(
            bytes.len() + chunk.len() <= limit,
            "Geodata response exceeds size limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn refresh(
    root: &Path,
    source: &Source,
    client: &Client,
    progress: &mut impl FnMut(String),
) -> Result<Outcome> {
    progress("Checking GeoIP / GeoSite updates…".into());
    let saved = load(root).unwrap_or_else(|error| {
        tracing::warn!(error=%error,"Ignoring invalid geodata cache");
        None
    });
    let mut request = client
        .get(&source.latest)
        .header(header::ACCEPT, "application/vnd.github+json");
    if let Some(etag) = saved.as_ref().and_then(|s| s.pointer.etag.as_ref()) {
        request = request.header(header::IF_NONE_MATCH, etag);
    }
    let response = request.send().await.map_err(|e| e.without_url())?;
    if response.status() == StatusCode::NOT_MODIFIED {
        return Ok(Outcome {
            snapshot: saved.context("Received 304 without a valid cache")?,
            updated: false,
        });
    }
    let etag = response
        .headers()
        .get(header::ETAG)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= 1024)
        .map(str::to_string);
    let release: Release = serde_json::from_slice(&response_bytes(response, MAX_METADATA).await?)?;
    anyhow::ensure!(
        !release.draft
            && !release.prerelease
            && !release.tag_name.is_empty()
            && release.tag_name.len() <= 128
            && release
                .tag_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "Invalid geodata release"
    );
    let asset = |name: &str, limit: usize| -> Result<Asset> {
        let found: Vec<_> = release.assets.iter().filter(|a| a.name == name).collect();
        anyhow::ensure!(
            found.len() == 1,
            "Missing or duplicate release asset {name}"
        );
        anyhow::ensure!(
            found[0].size > 0 && found[0].size <= limit as u64,
            "Invalid asset size for {name}"
        );
        Ok(found[0].clone())
    };
    let ip_asset = asset("geoip.dat", MAX_DATABASE)?;
    let site_asset = asset("geosite.dat", MAX_DATABASE)?;
    asset("geoip.dat.sha256sum", 4096)?;
    asset("geosite.dat.sha256sum", 4096)?;
    if let Some(mut saved) = saved.clone() {
        if saved.manifest.release_id == release.id
            && saved.manifest.version == release.tag_name
            && saved.manifest.geoip == ip_asset
            && saved.manifest.geosite == site_asset
        {
            saved.pointer.etag = etag;
            write_pointer(root, &saved.pointer)?;
            return Ok(Outcome {
                snapshot: saved,
                updated: false,
            });
        }
    }
    let mut hashes = vec![];
    for name in ["geoip.dat", "geosite.dat"] {
        let response = client
            .get(source.asset(&release.tag_name, &format!("{name}.sha256sum")))
            .send()
            .await
            .map_err(|e| e.without_url())?;
        hashes.push(checksum(&response_bytes(response, 4096).await?, name)?);
    }
    let releases = root.join("releases");
    fs::create_dir_all(&releases)?;
    let staging = tempfile::Builder::new()
        .prefix(".staging-")
        .tempdir_in(&releases)?;
    for ((name, asset), hash) in [("geoip.dat", &ip_asset), ("geosite.dat", &site_asset)]
        .into_iter()
        .zip(&hashes)
    {
        if let Some(digest) = &asset.digest {
            anyhow::ensure!(
                digest == &format!("sha256:{hash}"),
                "Release digest disagrees with checksum for {name}"
            );
        }
        // A matching verified file can be reused, even on the first launch.
        // The release checksum, not the tag alone, decides whether it matches.
        let cached = saved.as_ref().and_then(|snapshot| {
            let old_hash = if name == "geoip.dat" {
                &snapshot.manifest.geoip_sha256
            } else {
                &snapshot.manifest.geosite_sha256
            };
            if old_hash != hash {
                return None;
            }
            read_bounded(
                &releases.join(&snapshot.pointer.directory).join(name),
                MAX_DATABASE,
            )
            .ok()
        });
        let embedded = if name == "geoip.dat" {
            routing::BUNDLED_GEOIP
        } else {
            routing::BUNDLED_GEOSITE
        };
        let reusable = cached
            .as_deref()
            .filter(|bytes| bytes.len() as u64 == asset.size && verify(bytes, hash, name).is_ok())
            .or_else(|| {
                (embedded.len() as u64 == asset.size && verify(embedded, hash, name).is_ok())
                    .then_some(embedded)
            });
        if let Some(bytes) = reusable {
            progress(format!("Saving verified {name}…"));
            let mut file = fs::File::create(staging.path().join(name))?;
            file.write_all(bytes)?;
            file.sync_all()?;
            continue;
        }
        progress(format!("Downloading {name}…"));
        let response = client
            .get(source.asset(&release.tag_name, name))
            .send()
            .await
            .map_err(|e| e.without_url())?
            .error_for_status()
            .map_err(|e| e.without_url())?;
        anyhow::ensure!(
            response.content_length().unwrap_or(0) <= MAX_DATABASE as u64,
            "Oversized geodata asset"
        );
        let mut response = response;
        let mut file = fs::File::create(staging.path().join(name))?;
        let mut digest = Sha256::new();
        let mut count = 0usize;
        let mut reported = 0usize;
        while let Some(chunk) = response.chunk().await.map_err(|e| e.without_url())? {
            count += chunk.len();
            anyhow::ensure!(
                count <= MAX_DATABASE && count as u64 <= asset.size,
                "Oversized geodata asset"
            );
            file.write_all(&chunk)?;
            digest.update(&chunk);
            if count / 1_048_576 > reported {
                reported = count / 1_048_576;
                progress(format!(
                    "Downloading {name}: {} / {} MiB",
                    reported,
                    asset.size.div_ceil(1_048_576)
                ));
            }
        }
        anyhow::ensure!(count as u64 == asset.size, "Incomplete download for {name}");
        anyhow::ensure!(
            format!("{:x}", digest.finalize()) == *hash,
            "SHA-256 mismatch for {name}"
        );
        file.sync_all()?;
    }
    progress("Verifying GeoIP / GeoSite…".into());
    let data = routing::decode_geodata(
        &read_bounded(&staging.path().join("geoip.dat"), MAX_DATABASE)?,
        &read_bounded(&staging.path().join("geosite.dat"), MAX_DATABASE)?,
    )?;
    let manifest = Manifest {
        version: release.tag_name,
        release_id: release.id,
        geoip: ip_asset,
        geosite: site_asset,
        geoip_sha256: hashes[0].clone(),
        geosite_sha256: hashes[1].clone(),
    };
    let mut file = fs::File::create(staging.path().join("manifest.json"))?;
    file.write_all(&serde_json::to_vec_pretty(&manifest)?)?;
    file.sync_all()?;
    drop(file);
    let unique = staging
        .path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .trim_start_matches('.')
        .to_string();
    let directory = format!("release-{}-{unique}", release.id);
    fs::rename(staging.path(), releases.join(&directory))?;
    let pointer = Pointer { directory, etag };
    write_pointer(root, &pointer)?;
    Ok(Outcome {
        snapshot: Snapshot {
            manifest,
            pointer,
            data,
        },
        updated: true,
    })
}

fn write_pointer(root: &Path, pointer: &Pointer) -> Result<()> {
    fs::create_dir_all(root)?;
    let mut file = tempfile::NamedTempFile::new_in(root)?;
    file.write_all(&serde_json::to_vec(pointer)?)?;
    file.as_file().sync_all()?;
    file.persist(root.join("current.json"))
        .map_err(|e| e.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{Outbound, Router, RoutingConfig, Rule};
    use prost::Message;
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Minimal V2Ray wire fixtures. Tests never use a real profile or the app cache.
    #[derive(Clone, PartialEq, Message)]
    struct IpList {
        #[prost(message, repeated, tag = "1")]
        entries: Vec<Ip>,
    }
    #[derive(Clone, PartialEq, Message)]
    struct Ip {
        #[prost(string, tag = "1")]
        code: String,
        #[prost(message, repeated, tag = "2")]
        cidrs: Vec<Net>,
    }
    #[derive(Clone, PartialEq, Message)]
    struct Net {
        #[prost(bytes = "vec", tag = "1")]
        ip: Vec<u8>,
        #[prost(uint32, tag = "2")]
        prefix: u32,
    }
    #[derive(Clone, PartialEq, Message)]
    struct SiteList {
        #[prost(message, repeated, tag = "1")]
        entries: Vec<Site>,
    }
    #[derive(Clone, PartialEq, Message)]
    struct Site {
        #[prost(string, tag = "1")]
        code: String,
        #[prost(message, repeated, tag = "2")]
        domains: Vec<Domain>,
    }
    #[derive(Clone, PartialEq, Message)]
    struct Domain {
        #[prost(int32, tag = "1")]
        kind: i32,
        #[prost(string, tag = "2")]
        value: String,
    }

    fn fixture(version: u64) -> (Release, HashMap<String, Vec<u8>>) {
        let ips = IpList {
            entries: vec![
                Ip {
                    code: "IR".into(),
                    cidrs: vec![Net {
                        ip: vec![5, version as u8, 0, 0],
                        prefix: 16,
                    }],
                },
                Ip {
                    code: "PRIVATE".into(),
                    cidrs: vec![Net {
                        ip: vec![10, 0, 0, 0],
                        prefix: 8,
                    }],
                },
            ],
        }
        .encode_to_vec();
        let sites = SiteList {
            entries: ["google", "category-ads-all", &format!("new-{version}")]
                .into_iter()
                .map(|code| Site {
                    code: code.into(),
                    domains: vec![Domain {
                        kind: 2,
                        value: format!("new{version}.example"),
                    }],
                })
                .collect(),
        }
        .encode_to_vec();
        let mut files = HashMap::from([("geoip.dat".into(), ips), ("geosite.dat".into(), sites)]);
        for name in ["geoip.dat", "geosite.dat"] {
            files.insert(
                format!("{name}.sha256sum"),
                format!("{}  {name}\n", sha256(&files[name])).into_bytes(),
            );
        }
        let release = Release {
            id: version,
            tag_name: format!("v{version}"),
            draft: false,
            prerelease: false,
            assets: files
                .iter()
                .map(|(name, bytes)| Asset {
                    name: name.clone(),
                    id: version,
                    size: bytes.len() as u64,
                    updated_at: format!("revision-{version}"),
                    digest: Some(format!("sha256:{}", sha256(bytes))),
                })
                .collect(),
        };
        (release, files)
    }
    struct State {
        release: Release,
        files: HashMap<String, Vec<u8>>,
        requests: Vec<String>,
        not_modified: bool,
        unavailable: bool,
    }
    struct Server {
        source: Source,
        state: Arc<Mutex<State>>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    impl Server {
        async fn new() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let (release, files) = fixture(160);
            let state = Arc::new(Mutex::new(State {
                release,
                files,
                requests: vec![],
                not_modified: false,
                unavailable: false,
            }));
            let shared = state.clone();
            let task = tokio::spawn(async move {
                loop {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let shared = shared.clone();
                    tokio::spawn(async move {
                        let mut request = vec![];
                        loop {
                            let mut buf = [0; 1024];
                            let n = socket.read(&mut buf).await.unwrap();
                            if n == 0 {
                                return;
                            }
                            request.extend_from_slice(&buf[..n]);
                            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                            assert!(request.len() < 16384);
                        }
                        let request = String::from_utf8(request).unwrap();
                        let path = request.split_whitespace().nth(1).unwrap();
                        let (status, body) = {
                            let mut state = shared.lock().unwrap();
                            state.requests.push(request.clone());
                            if state.unavailable {
                                ("503 Service Unavailable", vec![])
                            } else if path == "/latest" {
                                if state.not_modified {
                                    ("304 Not Modified", vec![])
                                } else {
                                    ("200 OK", serde_json::to_vec(&state.release).unwrap())
                                }
                            } else {
                                match state.files.get(path.rsplit('/').next().unwrap()) {
                                    Some(bytes) => ("200 OK", bytes.clone()),
                                    None => ("404 Not Found", vec![]),
                                }
                            }
                        };
                        let head=format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nETag: \"fixture\"\r\nConnection: close\r\n\r\n",body.len());
                        socket.write_all(head.as_bytes()).await.unwrap();
                        let _ = socket.write_all(&body).await;
                    });
                }
            });
            Self {
                source: Source {
                    latest: format!("{origin}/latest"),
                    downloads: format!("{origin}/download"),
                },
                state,
                task,
            }
        }
        async fn refresh(&self, root: &Path) -> Result<Outcome> {
            refresh(root, &self.source, &client(None)?, &mut |_| {}).await
        }
        fn set_version(&self, version: u64) {
            let (release, files) = fixture(version);
            let mut state = self.state.lock().unwrap();
            state.release = release;
            state.files = files;
        }
    }

    #[tokio::test]
    async fn downloads_verified_pair_reuses_etag_and_activates_new_rules() {
        let root = tempfile::tempdir().unwrap();
        let server = Server::new().await;
        let first = server.refresh(root.path()).await.unwrap();
        assert!(first.updated);
        assert_eq!(first.snapshot.manifest.version, "v160");
        assert!(load(root.path()).unwrap().is_some());
        let initial = fs::read(root.path().join("current.json")).unwrap();
        {
            let mut s = server.state.lock().unwrap();
            s.not_modified = true;
            s.requests.clear();
        }
        assert!(!server.refresh(root.path()).await.unwrap().updated);
        {
            let s = server.state.lock().unwrap();
            assert_eq!(s.requests.len(), 1);
            assert!(s.requests[0]
                .to_lowercase()
                .contains("if-none-match: \"fixture\""));
        }
        {
            let mut s = server.state.lock().unwrap();
            s.not_modified = false;
            s.requests.clear();
        }
        assert!(!server.refresh(root.path()).await.unwrap().updated);
        assert_eq!(
            server.state.lock().unwrap().requests.len(),
            1,
            "unchanged release must not download assets"
        );
        server.set_version(161);
        let next = server.refresh(root.path()).await.unwrap();
        assert!(next.updated);
        assert_ne!(initial, fs::read(root.path().join("current.json")).unwrap());
        let config = RoutingConfig {
            rules: vec![
                Rule {
                    name: "new sites".into(),
                    outbound: Outbound::Block,
                    domains: vec!["geosite:new-161".into()],
                    ..Rule::default()
                },
                Rule {
                    name: "Iran".into(),
                    outbound: Outbound::Direct,
                    ips: vec!["geoip:ir".into()],
                    ..Rule::default()
                },
            ],
            ..RoutingConfig::default()
        };
        let router =
            Router::build_with_data(config, &BTreeMap::new(), &[], next.snapshot.data).unwrap();
        assert_eq!(
            router.evaluate("new161.example", &[]).outbound,
            Outbound::Block
        );
        assert_eq!(router.evaluate("5.161.0.1", &[]).outbound, Outbound::Direct);
        assert_eq!(router.evaluate("5.160.0.1", &[]).outbound, Outbound::Proxy);
    }

    #[tokio::test]
    async fn failed_or_invalid_updates_preserve_complete_saved_pair() {
        let root = tempfile::tempdir().unwrap();
        let server = Server::new().await;
        server.refresh(root.path()).await.unwrap();
        let pointer = fs::read(root.path().join("current.json")).unwrap();
        server.set_version(161);
        server
            .state
            .lock()
            .unwrap()
            .files
            .get_mut("geosite.dat")
            .unwrap()
            .pop();
        assert!(
            server.refresh(root.path()).await.is_err(),
            "truncated download must fail"
        );
        assert_eq!(pointer, fs::read(root.path().join("current.json")).unwrap());
        server.set_version(161);
        server
            .state
            .lock()
            .unwrap()
            .files
            .get_mut("geosite.dat")
            .unwrap()[0] ^= 255;
        assert!(server.refresh(root.path()).await.is_err());
        assert_eq!(pointer, fs::read(root.path().join("current.json")).unwrap());
        server.set_version(161);
        {
            let mut s = server.state.lock().unwrap();
            let invalid = b"invalid protobuf".to_vec();
            s.files.insert("geosite.dat".into(), invalid.clone());
            s.files.insert(
                "geosite.dat.sha256sum".into(),
                sha256(&invalid).into_bytes(),
            );
            let asset = s
                .release
                .assets
                .iter_mut()
                .find(|a| a.name == "geosite.dat")
                .unwrap();
            asset.size = invalid.len() as u64;
            asset.digest = None;
        }
        assert!(server.refresh(root.path()).await.is_err());
        assert_eq!(pointer, fs::read(root.path().join("current.json")).unwrap());
        server.state.lock().unwrap().unavailable = true;
        assert!(server.refresh(root.path()).await.is_err());
        let saved = load(root.path()).unwrap().unwrap();
        assert_eq!(saved.manifest.version, "v160");
        // Staging downloads are automatically removed even after a failure.
        assert_eq!(
            fs::read_dir(root.path().join("releases")).unwrap().count(),
            1
        );
    }

    #[tokio::test]
    async fn same_tag_asset_replacement_is_detected() {
        let root = tempfile::tempdir().unwrap();
        let server = Server::new().await;
        server.refresh(root.path()).await.unwrap();
        server
            .state
            .lock()
            .unwrap()
            .release
            .assets
            .iter_mut()
            .for_each(|a| a.id += 1);
        assert!(server.refresh(root.path()).await.unwrap().updated);
    }

    #[tokio::test]
    async fn unchanged_file_is_reused_when_the_other_database_changes() {
        let root = tempfile::tempdir().unwrap();
        let server = Server::new().await;
        server.refresh(root.path()).await.unwrap();
        let (_, old_files) = fixture(160);
        server.set_version(161);
        {
            let mut state = server.state.lock().unwrap();
            for name in ["geoip.dat", "geoip.dat.sha256sum"] {
                state.files.insert(name.into(), old_files[name].clone());
                let asset = state
                    .release
                    .assets
                    .iter_mut()
                    .find(|a| a.name == name)
                    .unwrap();
                asset.size = old_files[name].len() as u64;
                asset.digest = Some(format!("sha256:{}", sha256(&old_files[name])));
            }
            state.requests.clear();
        }
        assert!(server.refresh(root.path()).await.unwrap().updated);
        let state = server.state.lock().unwrap();
        assert!(!state
            .requests
            .iter()
            .any(|r| r.starts_with("GET /download/v161/geoip.dat HTTP")));
        assert!(state
            .requests
            .iter()
            .any(|r| r.starts_with("GET /download/v161/geosite.dat HTTP")));
        assert_eq!(load(root.path()).unwrap().unwrap().manifest.version, "v161");
    }

    #[tokio::test]
    async fn updater_uses_socks_remote_dns_before_any_system_proxy_exists() {
        let root = tempfile::tempdir().unwrap();
        let server = Server::new().await;
        let origin = reqwest::Url::parse(&server.source.latest).unwrap();
        let origin_addr = format!("127.0.0.1:{}", origin.port().unwrap());
        let socks = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = socks.local_addr().unwrap();
        let names = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen = names.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = socks.accept().await.unwrap();
                let origin_addr = origin_addr.clone();
                let seen = seen.clone();
                tokio::spawn(async move {
                    let mut greeting = [0; 3];
                    socket.read_exact(&mut greeting).await.unwrap();
                    assert_eq!(greeting, [5, 1, 0]);
                    socket.write_all(&[5, 0]).await.unwrap();
                    let mut request = [0; 5];
                    socket.read_exact(&mut request).await.unwrap();
                    assert_eq!(&request[..4], &[5, 1, 0, 3]);
                    let mut name = vec![0; request[4] as usize];
                    socket.read_exact(&mut name).await.unwrap();
                    seen.lock().unwrap().push(String::from_utf8(name).unwrap());
                    let mut port = [0; 2];
                    socket.read_exact(&mut port).await.unwrap();
                    let mut upstream = tokio::net::TcpStream::connect(&origin_addr).await.unwrap();
                    socket
                        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                        .await
                        .unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut socket, &mut upstream).await;
                });
            }
        });
        let source = Source {
            latest: "http://geodata-source.invalid/latest".into(),
            downloads: "http://geodata-source.invalid/download".into(),
        };
        assert!(
            refresh(
                root.path(),
                &source,
                &client(Some(backend)).unwrap(),
                &mut |_| {}
            )
            .await
            .unwrap()
            .updated
        );
        assert!(names.lock().unwrap().len() >= 5);
        assert!(names
            .lock()
            .unwrap()
            .iter()
            .all(|name| name == "geodata-source.invalid"));
        task.abort();
    }

    #[tokio::test]
    async fn bad_cache_is_rejected_and_repaired_without_conditional_request() {
        let root = tempfile::tempdir().unwrap();
        let server = Server::new().await;
        let first = server.refresh(root.path()).await.unwrap();
        let data_dir = root
            .path()
            .join("releases")
            .join(first.snapshot.pointer.directory);
        fs::write(data_dir.join("geoip.dat"), b"damaged").unwrap();
        assert!(load(root.path()).is_err());
        server.state.lock().unwrap().requests.clear();
        assert!(server.refresh(root.path()).await.unwrap().updated);
        assert!(!server.state.lock().unwrap().requests[0]
            .to_lowercase()
            .contains("if-none-match"));
        assert!(load(root.path()).unwrap().is_some());
        fs::remove_file(
            root.path()
                .join("releases")
                .join(load(root.path()).unwrap().unwrap().pointer.directory)
                .join("geosite.dat"),
        )
        .unwrap();
        assert!(load(root.path()).is_err());
    }

    #[tokio::test]
    async fn oversized_or_incomplete_release_cannot_replace_pointer() {
        let root = tempfile::tempdir().unwrap();
        let server = Server::new().await;
        server.refresh(root.path()).await.unwrap();
        let pointer = fs::read(root.path().join("current.json")).unwrap();
        server.set_version(161);
        server
            .state
            .lock()
            .unwrap()
            .release
            .assets
            .iter_mut()
            .find(|a| a.name == "geoip.dat")
            .unwrap()
            .size = MAX_DATABASE as u64 + 1;
        assert!(server.refresh(root.path()).await.is_err());
        server.set_version(161);
        server
            .state
            .lock()
            .unwrap()
            .release
            .assets
            .retain(|a| a.name != "geosite.dat");
        assert!(server.refresh(root.path()).await.is_err());
        assert_eq!(pointer, fs::read(root.path().join("current.json")).unwrap());
    }

    #[test]
    fn traversal_and_invalid_checksums_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        write_pointer(
            root.path(),
            &Pointer {
                directory: "release-../../other".into(),
                etag: None,
            },
        )
        .unwrap();
        assert!(load(root.path()).is_err());
        assert!(checksum(
            format!("{} other.dat", sha256(b"x")).as_bytes(),
            "geoip.dat"
        )
        .is_err());
        assert!(checksum(b"short", "geoip.dat").is_err());
        assert!(routing::decode_geodata(&[], &[]).is_err());
    }

    #[test]
    fn bundled_fallback_is_valid_independently_of_user_cache() {
        assert!(routing::bundled_geodata().is_ok());
    }
}
