//! Desktop routing: v2rayN-style ordered rules and V2Ray geodata.
//! The rVPN wire protocol is unchanged. Only the local outbound is selected here.
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use prost::Message;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::profile::Profile;
use rvpn_mobile::rvpn_split_tunnel::DnsResolver;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outbound {
    Direct,
    #[default]
    Proxy,
    Block,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainStrategy {
    AsIs,
    #[default]
    IPIfNonMatch,
    IPOnDemand,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Rule {
    pub name: String,
    pub enabled: bool,
    pub outbound: Outbound,
    pub domains: Vec<String>,
    pub ips: Vec<String>,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            name: "New rule".into(),
            enabled: true,
            outbound: Outbound::Direct,
            domains: vec![],
            ips: vec![],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RoutingConfig {
    pub strategy: DomainStrategy,
    pub default_outbound: Outbound,
    pub rules: Vec<Rule>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            strategy: DomainStrategy::IPIfNonMatch,
            default_outbound: Outbound::Proxy,
            rules: vec![],
        }
    }
}

impl RoutingConfig {
    pub fn iran_direct() -> Self {
        Self {
            rules: vec![
                Rule {
                    name: "Iranian domains".into(),
                    domains: vec!["domain:ir".into(), "domain:xn--mgba3a4f16a".into()],
                    ..Rule::default()
                },
                Rule {
                    name: "Iran and private networks".into(),
                    ips: vec!["geoip:ir".into(), "geoip:private".into()],
                    ..Rule::default()
                },
            ],
            ..Self::default()
        }
    }

    /// Preserve old profiles; no disk/profile migration until the user saves.
    pub fn from_profile(profile: &Profile) -> Self {
        if let Some(config) = &profile.routing {
            return config.clone();
        }
        let mut config = Self::default();
        if !profile.split_tunnel_enabled {
            return config;
        }
        if !profile.tunnel_domains.is_empty() {
            config.rules.push(Rule {
                name: "Existing proxy domains".into(),
                outbound: Outbound::Proxy,
                domains: legacy_domains(&profile.tunnel_domains),
                ..Rule::default()
            });
        }
        if !profile.bypass_domains.is_empty() {
            config.rules.push(Rule {
                name: "Existing direct domains".into(),
                domains: legacy_domains(&profile.bypass_domains),
                ..Rule::default()
            });
        }
        let mut ips = profile.bypass_networks.clone();
        ips.extend(
            profile
                .builtin_bypass_countries
                .iter()
                .map(|c| format!("geoip:{}", c.to_ascii_lowercase())),
        );
        if !ips.is_empty() {
            config.rules.push(Rule {
                name: "Existing direct networks".into(),
                ips,
                ..Rule::default()
            });
        }
        config
    }
}

fn legacy_domains(domains: &[String]) -> Vec<String> {
    domains
        .iter()
        .map(|d| {
            if d.contains(':') || d.starts_with("*.") {
                d.clone()
            } else {
                format!("domain:{d}")
            }
        })
        .collect()
}

/// Compiled form of the routing rules for full-tunnel (TUN) mode.
///
/// TUN routing happens in the OS route table, so only address-shaped rules
/// can steer it: country codes (GeoIP) and CIDRs become bypass routes next
/// to the engine's builtin LAN bypass. Domain lists ride along for the
/// engine's DNS layer and apply fully in proxy mode. `geoip:private` is
/// skipped — the builtin LAN bypass already covers RFC1918.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TunnelSplit {
    /// GeoIP country codes whose traffic bypasses the tunnel (e.g. `IR`).
    pub countries: Vec<String>,
    /// Those countries expanded to CIDRs from the app's GeoIP database —
    /// the OS route table and the engine both get these directly.
    pub country_cidrs: Vec<String>,
    /// CIDRs routed outside the tunnel.
    pub networks: Vec<String>,
    /// Domains routed outside the tunnel (engine suffix/`*.` form).
    pub bypass_domains: Vec<String>,
    /// Domains forced through the tunnel even when other rules bypass.
    pub tunnel_domains: Vec<String>,
}

impl RoutingConfig {
    /// Compile the enabled rules into the engine's tunnel-mode fields.
    ///
    /// `geoip:XX` codes are expanded through the app's own GeoIP database
    /// (the same one proxy mode matches with — auto-updated, and it has
    /// every country). The engine's compiled-in country table only knows a
    /// handful of Asian codes, so it cannot be trusted for e.g. `geoip:ir`.
    pub fn tunnel_split(&self) -> Result<TunnelSplit> {
        let mut split = TunnelSplit::default();
        for rule in self.rules.iter().filter(|r| r.enabled) {
            for pattern in &rule.ips {
                let pattern = pattern.trim();
                if let Some(code) = pattern.strip_prefix("geoip:") {
                    let code = code.trim().to_ascii_uppercase();
                    if code == "PRIVATE" {
                        continue; // builtin LAN bypass already covers it
                    }
                    if code.is_empty() {
                        continue;
                    }
                    if !split.countries.contains(&code) {
                        let cidrs = expand_country(&code)?;
                        if cidrs.is_empty() {
                            bail!("Unknown geoip:{code}");
                        }
                        split.countries.push(code);
                        split.country_cidrs.extend(cidrs);
                    }
                } else if let Ok(net) = pattern.parse::<IpNetwork>() {
                    let net = net.to_string();
                    if !split.networks.contains(&net) {
                        split.networks.push(net);
                    }
                }
            }
            let sink = match rule.outbound {
                Outbound::Direct => &mut split.bypass_domains,
                Outbound::Proxy => &mut split.tunnel_domains,
                // The engine's TUN blocklist is ads-only today; Block rules
                // keep applying in proxy mode and via ad blocking.
                Outbound::Block => continue,
            };
            for domain in &rule.domains {
                // Rule form (`domain:x`) back to the engine's plain-suffix
                // form; wildcards pass through untouched.
                let d = domain.trim();
                let d = d.strip_prefix("domain:").unwrap_or(d);
                if !d.is_empty() && !sink.iter().any(|e| e == d) {
                    sink.push(d.to_string());
                }
            }
        }
        Ok(split)
    }
}

/// Expand a country code to CIDRs via the active GeoIP database.
fn expand_country(code: &str) -> Result<Vec<String>> {
    let data = geodata()?;
    let entry = data
        .ips
        .get(&code.to_ascii_lowercase())
        .with_context(|| format!("Unknown geoip:{code}"))?;
    entry
        .cidr
        .iter()
        .map(|c| Ok(cidr_network(c)?.to_string()))
        .collect()
}

// Wire definitions from v2fly/v2ray-core app/router/routercommon/common.proto.
// Unknown protobuf fields are ignored, permitting newer databases.
#[derive(Clone, PartialEq, Message)]
struct GeoIpList {
    #[prost(message, repeated, tag = "1")]
    entry: Vec<GeoIp>,
}
#[derive(Clone, PartialEq, Message)]
struct GeoIp {
    #[prost(string, tag = "1")]
    country_code: String,
    #[prost(message, repeated, tag = "2")]
    cidr: Vec<Cidr>,
    #[prost(bool, tag = "3")]
    inverse_match: bool,
}
#[derive(Clone, PartialEq, Message)]
struct Cidr {
    #[prost(bytes = "vec", tag = "1")]
    ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    prefix: u32,
}
#[derive(Clone, PartialEq, Message)]
struct GeoSiteList {
    #[prost(message, repeated, tag = "1")]
    entry: Vec<GeoSite>,
}
#[derive(Clone, PartialEq, Message)]
struct GeoSite {
    #[prost(string, tag = "1")]
    country_code: String,
    #[prost(message, repeated, tag = "2")]
    domain: Vec<GeoDomain>,
}
#[derive(Clone, PartialEq, Message)]
struct GeoDomain {
    #[prost(int32, tag = "1")]
    kind: i32,
    #[prost(string, tag = "2")]
    value: String,
    #[prost(message, repeated, tag = "3")]
    attribute: Vec<Attribute>,
}
#[derive(Clone, PartialEq, Message)]
struct Attribute {
    #[prost(string, tag = "1")]
    key: String,
}

pub(crate) struct GeoData {
    ips: BTreeMap<String, GeoIp>,
    sites: BTreeMap<String, GeoSite>,
}
static BUNDLED: OnceLock<std::result::Result<Arc<GeoData>, String>> = OnceLock::new();
static ACTIVE: RwLock<Option<Arc<GeoData>>> = RwLock::new(None);
pub(crate) const BUNDLED_GEOIP: &[u8] = include_bytes!("../../../assets/geoip.dat");
pub(crate) const BUNDLED_GEOSITE: &[u8] = include_bytes!("../../../assets/geosite.dat");

pub(crate) fn decode_geodata(ips: &[u8], sites: &[u8]) -> Result<Arc<GeoData>> {
    let ips = GeoIpList::decode(ips).context("Invalid GeoIP protobuf")?;
    let sites = GeoSiteList::decode(sites).context("Invalid GeoSite protobuf")?;
    anyhow::ensure!(!ips.entry.is_empty() && !sites.entry.is_empty(), "Empty geodata database");
    for entry in &ips.entry {
        anyhow::ensure!(!entry.country_code.is_empty() && !entry.cidr.is_empty(), "Empty GeoIP entry");
        for cidr in &entry.cidr { cidr_network(cidr)?; }
    }
    for entry in &sites.entry {
        anyhow::ensure!(!entry.country_code.is_empty() && !entry.domain.is_empty(), "Empty GeoSite entry");
        for domain in &entry.domain {
            anyhow::ensure!((0..=3).contains(&domain.kind) && !domain.value.is_empty(), "Invalid GeoSite domain");
            if domain.kind == 1 { Regex::new(&domain.value).context("Unsupported GeoSite regex")?; }
        }
    }
    let data = GeoData {
        ips: ips.entry.into_iter().map(|e|(e.country_code.to_ascii_lowercase(),e)).collect(),
        sites: sites.entry.into_iter().map(|e|(e.country_code.to_ascii_lowercase(),e)).collect(),
    };
    anyhow::ensure!(data.ips.contains_key("ir") && data.ips.contains_key("private"), "GeoIP is missing IR/private");
    anyhow::ensure!(data.sites.contains_key("google") && data.sites.contains_key("category-ads-all"), "GeoSite is missing required groups");
    Ok(Arc::new(data))
}

pub(crate) fn bundled_geodata() -> Result<Arc<GeoData>> {
    BUNDLED.get_or_init(||decode_geodata(BUNDLED_GEOIP,BUNDLED_GEOSITE)
        .map_err(|e|format!("{e:#}"))).as_ref().cloned().map_err(|e|anyhow::anyhow!("Invalid bundled geodata: {e}"))
}

pub(crate) fn activate_geodata(data: Arc<GeoData>) {
    *ACTIVE.write().unwrap() = Some(data);
}

fn geodata() -> Result<Arc<GeoData>> {
    if let Some(data) = ACTIVE.read().unwrap().as_ref() { return Ok(data.clone()); }
    let data = crate::geodata::load_cached_data().unwrap_or_else(|error| {
        tracing::warn!(error = %format!("{error:#}"), "cached geodata unavailable; using bundled snapshot");
        None
    }).map(Ok).unwrap_or_else(bundled_geodata)?;
    let mut active = ACTIVE.write().unwrap();
    Ok(active.get_or_insert(data).clone())
}

pub fn country_codes() -> Vec<String> {
    geodata()
        .map(|g| {
            g.ips
                .keys()
                .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphabetic()))
                .map(|c| c.to_ascii_uppercase())
                .collect()
        })
        .unwrap_or_default()
}

pub fn geosite_groups() -> Vec<String> {
    geodata()
        .map(|g| g.sites.keys().cloned().collect())
        .unwrap_or_default()
}

enum DomainMatch {
    Plain(String),
    Suffix(String),
    Full(String),
    Wildcard(String),
    Regex(Regex),
}
impl DomainMatch {
    fn matches(&self, host: &str) -> bool {
        match self {
            Self::Plain(v) => host.contains(v),
            Self::Suffix(v) => host == v || host.strip_suffix(v).is_some_and(|s| s.ends_with('.')),
            Self::Full(v) => host == v,
            Self::Wildcard(v) => host.strip_suffix(v).is_some_and(|s| s.ends_with('.')),
            Self::Regex(v) => v.is_match(host),
        }
    }
}

struct CompiledRule {
    name: String,
    outbound: Outbound,
    domains: Vec<DomainMatch>,
    ips: IpNetworkTable<bool>,
    inverse_ips: Vec<IpNetworkTable<bool>>,
}
impl CompiledRule {
    fn matches_ip(&self, ip: IpAddr) -> bool {
        self.ips.longest_match(ip).is_some()
            || self
                .inverse_ips
                .iter()
                .any(|t| t.longest_match(ip).is_none())
    }
    fn has_ips(&self) -> bool {
        self.ips.iter().next().is_some() || !self.inverse_ips.is_empty()
    }
}

pub struct Router {
    config: RoutingConfig,
    rules: Vec<CompiledRule>,
    resolver: Arc<DnsResolver>,
    tunnel_dns: Option<crate::tunnel_dns::TunnelDns>,
}

#[derive(Debug)]
pub struct Route {
    pub outbound: Outbound,
    pub rule: String,
    /// Direct IPs selected by the rule, reused for dialing (no second DNS lookup).
    pub direct_ips: Vec<IpAddr>,
}

impl Router {
    pub fn for_profile(profile: &Profile) -> Result<Self> {
        let custom: BTreeMap<String, Vec<String>> = if let Some(file) = &profile.country_ips_file {
            let file = profile.dir().join(file);
            serde_json::from_str(
                &std::fs::read_to_string(&file)
                    .with_context(|| format!("Cannot load {}", file.display()))?,
            )?
        } else {
            BTreeMap::new()
        };
        let mut config = RoutingConfig::from_profile(profile);
        if profile.block_ads {
            config.rules.insert(
                0,
                Rule {
                    name: "Ad / tracker blocking".into(),
                    outbound: Outbound::Block,
                    domains: vec!["geosite:category-ads-all".into()],
                    ..Rule::default()
                },
            );
        }
        Self::build(config, &custom, &profile.bypass_dns_servers)
    }

    pub fn build(
        config: RoutingConfig,
        custom: &BTreeMap<String, Vec<String>>,
        dns: &[String],
    ) -> Result<Self> {
        Self::build_with_data(config,custom,dns,geodata()?)
    }

    pub(crate) fn build_with_data(
        config: RoutingConfig, custom: &BTreeMap<String,Vec<String>>, dns: &[String], geo: Arc<GeoData>,
    ) -> Result<Self> {
        let custom: BTreeMap<_, _> = custom
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();
        let mut rules = vec![];
        for (index, rule) in config.rules.iter().enumerate().filter(|(_, r)| r.enabled) {
            if rule.domains.is_empty() && rule.ips.is_empty() {
                bail!("Rule {} ({}) is empty", index + 1, rule.name);
            }
            let mut compiled = CompiledRule {
                name: rule.name.clone(),
                outbound: rule.outbound,
                domains: vec![],
                ips: IpNetworkTable::new(),
                inverse_ips: vec![],
            };
            for pattern in &rule.domains {
                let pattern = pattern.trim();
                if let Some(group) = pattern.strip_prefix("geosite:") {
                    let previous_count = compiled.domains.len();
                    let (group, attribute) = group
                        .split_once('@')
                        .map(|(g, a)| (g, Some(a)))
                        .unwrap_or((group, None));
                    let site = geo
                        .sites
                        .get(&group.to_ascii_lowercase())
                        .with_context(|| format!("Unknown geosite:{group}"))?;
                    for domain in &site.domain {
                        if attribute.is_some_and(|a| {
                            !domain
                                .attribute
                                .iter()
                                .any(|v| v.key.eq_ignore_ascii_case(a))
                        }) {
                            continue;
                        }
                        compiled.domains.push(parse_domain(&match domain.kind {
                            0 => domain.value.clone(),
                            1 => format!("regexp:{}", domain.value),
                            2 => format!("domain:{}", domain.value),
                            3 => format!("full:{}", domain.value),
                            _ => bail!("Unknown geosite domain kind"),
                        })?);
                    }
                    if compiled.domains.len() == previous_count {
                        bail!("No domains in {pattern}");
                    }
                } else {
                    compiled.domains.push(
                        parse_domain(pattern).with_context(|| format!("Rule {}", index + 1))?,
                    );
                }
            }
            for pattern in &rule.ips {
                if let Some(code) = pattern.trim().strip_prefix("geoip:") {
                    let inverse = code.starts_with('!');
                    let code = code.trim_start_matches('!').to_ascii_lowercase();
                    let mut table = IpNetworkTable::new();
                    if let Some(cidrs) = custom.get(&code) {
                        if cidrs.is_empty() {
                            bail!("Empty country database for {code}");
                        }
                        for cidr in *cidrs {
                            table.insert(parse_network(cidr)?, true);
                        }
                    } else {
                        let entry = geo
                            .ips
                            .get(&code)
                            .with_context(|| format!("Unknown geoip:{code}"))?;
                        if entry.inverse_match {
                            bail!("Unsupported inverse database entry {code}");
                        }
                        for cidr in &entry.cidr {
                            table.insert(cidr_network(cidr)?, true);
                        }
                    }
                    if inverse {
                        compiled.inverse_ips.push(table);
                    } else {
                        for (network, _) in table.iter() {
                            compiled.ips.insert(network, true);
                        }
                    }
                } else {
                    compiled.ips.insert(parse_network(pattern)?, true);
                }
            }
            rules.push(compiled);
        }
        let nameservers: Vec<SocketAddr> = dns
            .iter()
            .map(|d| {
                d.parse::<SocketAddr>()
                    .or_else(|_| d.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
            })
            .collect::<std::result::Result<_, _>>()
            .context("Invalid direct DNS server")?;
        Ok(Self {
            config,
            rules,
            resolver: Arc::new(DnsResolver::new(true, 300, 4096, true, true, nameservers)),
            tunnel_dns: None,
        })
    }

    /// Production proxy mode uses tunneled DNS to classify destinations.
    /// Explicit Direct domains still resolve through the direct resolver.
    pub fn with_tunnel_dns(mut self, backend: SocketAddr, servers: &[String]) -> Result<Self> {
        self.tunnel_dns = Some(crate::tunnel_dns::TunnelDns::new(backend, servers)?);
        Ok(self)
    }

    fn matched(&self, host: &str, ips: &[IpAddr]) -> Option<Route> {
        for rule in &self.rules {
            let domain =
                host.parse::<IpAddr>().is_err() && rule.domains.iter().any(|d| d.matches(host));
            let matched_ips: Vec<_> = ips
                .iter()
                .copied()
                .filter(|ip| rule.matches_ip(*ip))
                .collect();
            // v2rayN emits domain and IP entries as separate field rules (OR).
            if domain || !matched_ips.is_empty() {
                return Some(Route {
                    outbound: rule.outbound,
                    rule: rule.name.clone(),
                    direct_ips: if domain { ips.to_vec() } else { matched_ips },
                });
            }
        }
        None
    }

    /// Deterministic entry point also used by the route tester.
    pub fn evaluate(&self, host: &str, ips: &[IpAddr]) -> Route {
        let host = normalize_host(host);
        let literal = host.parse::<IpAddr>().ok();
        let literal_ips: Vec<_> = literal.into_iter().collect();
        let ips = if literal_ips.is_empty() {
            ips
        } else {
            &literal_ips
        };
        if self.config.strategy != DomainStrategy::IPOnDemand && literal_ips.is_empty() {
            if let Some(route) = self.matched(&host, &[]) {
                return route;
            }
            if self.config.strategy == DomainStrategy::AsIs {
                return self.fallback(ips);
            }
        }
        self.matched(&host, ips)
            .unwrap_or_else(|| self.fallback(ips))
    }

    fn fallback(&self, ips: &[IpAddr]) -> Route {
        Route {
            outbound: self.config.default_outbound,
            rule: "Default route".into(),
            direct_ips: ips.to_vec(),
        }
    }

    pub async fn route(&self, host: &str) -> Result<Route> {
        let host = normalize_host(host);
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(self.evaluate(&host, &[ip]));
        }
        if self.config.strategy != DomainStrategy::IPOnDemand {
            if let Some(route) = self.matched(&host, &[]) {
                return Ok(route);
            }
        } else {
            // IPOnDemand only resolves when evaluation reaches an IP rule.
            for rule in &self.rules {
                if rule.domains.iter().any(|d| d.matches(&host)) {
                    return Ok(Route {
                        outbound: rule.outbound,
                        rule: rule.name.clone(),
                        direct_ips: vec![],
                    });
                }
                if rule.has_ips() {
                    break;
                }
            }
        }
        if self.config.strategy == DomainStrategy::AsIs || !self.rules.iter().any(|r| r.has_ips()) {
            return Ok(self.fallback(&[]));
        }
        // DNS is only for routing, not for replacing a proxied destination.
        // A failure must not quietly turn an intended direct route into proxy.
        let resolution = if let Some(dns) = &self.tunnel_dns {
            tokio::time::timeout(Duration::from_secs(15), dns.resolve(&host))
                .await
                .context("Tunnel routing DNS timed out")
                .and_then(|r| r)
        } else {
            tokio::time::timeout(Duration::from_secs(5), self.resolver.resolve(&host, 0))
                .await
                .context("Routing DNS timed out")
                .and_then(|r| r)
                .map(|addrs| addrs.iter().map(|a| a.ip()).collect())
        };
        let ips = match resolution {
            Ok(ips) => ips,
            Err(error) => {
                // A later explicit domain rule still applies if IPOnDemand
                // could not obtain IPs for an earlier network rule.
                if let Some(route) = self.matched(&host, &[]) {
                    return Ok(route);
                }
                return Err(error);
            }
        };
        Ok(self.evaluate(&host, &ips))
    }

    pub async fn direct_addresses(
        &self,
        host: &str,
        port: u16,
        route: &Route,
    ) -> Result<Vec<SocketAddr>> {
        if !route.direct_ips.is_empty() {
            return Ok(route
                .direct_ips
                .iter()
                .map(|ip| SocketAddr::new(*ip, port))
                .collect());
        }
        Ok(
            tokio::time::timeout(Duration::from_secs(5), self.resolver.resolve(host, port))
                .await
                .context("Direct DNS timed out")??,
        )
    }
}

fn normalize_host(host: &str) -> String {
    let host = host.trim_matches(['[', ']']).trim_end_matches('.');
    url::Host::parse(host)
        .map(|h| h.to_string())
        .unwrap_or_else(|_| host.to_ascii_lowercase())
        .trim_matches(['[', ']'])
        .to_ascii_lowercase()
}
fn parse_domain(pattern: &str) -> Result<DomainMatch> {
    if let Some(regex) = pattern.strip_prefix("regexp:") {
        return Ok(DomainMatch::Regex(Regex::new(regex)?));
    }
    let (kind, value) = if let Some(v) = pattern.strip_prefix("domain:") {
        (1, v)
    } else if let Some(v) = pattern.strip_prefix("full:") {
        (2, v)
    } else if let Some(v) = pattern.strip_prefix("*.") {
        (3, v)
    } else {
        (0, pattern)
    };
    if value.is_empty() || value.contains([':', '/', '*']) || value.chars().any(char::is_whitespace)
    {
        bail!("Invalid domain rule: {pattern}");
    }
    let value = normalize_host(value);
    Ok(match kind {
        1 => DomainMatch::Suffix(value),
        2 => DomainMatch::Full(value),
        3 => DomainMatch::Wildcard(value),
        _ => DomainMatch::Plain(value),
    })
}
fn parse_network(value: &str) -> Result<IpNetwork> {
    let value = value.trim();
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(IpNetwork::new(ip, if ip.is_ipv4() { 32 } else { 128 })?);
    }
    value
        .parse()
        .with_context(|| format!("Invalid IP/CIDR: {value}"))
}
fn cidr_network(cidr: &Cidr) -> Result<IpNetwork> {
    let ip = match cidr.ip.len() {
        4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(cidr.ip.as_slice())?)),
        16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(cidr.ip.as_slice())?)),
        _ => bail!("Invalid IP in geodata"),
    };
    Ok(IpNetwork::new(ip, u8::try_from(cidr.prefix)?)?)
}
