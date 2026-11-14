//! Connection profiles — the Windows mirror of the macOS app's profile model.
//!
//! Each profile owns a private directory under `<app_data>/profiles/<slug>/`
//! holding `identity.key` and `prekey-bundle.json`. Profile metadata lives in
//! a single `profiles.json` index. Profiles import/export as `.rvpn` JSON
//! files (with or without the private identity key), carrying the TOFU pin
//! so recipients inherit trust — same semantics as the macOS app.

use std::fmt;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::paths;

pub const MAX_PROFILES: usize = 10;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Profile {
    /// Unique slug used for the on-disk directory (ASCII, filesystem-safe).
    pub slug: String,
    /// Display name.
    pub name: String,
    /// Server WebSocket address, e.g. `wss://sg.example.com:443/api/v1/ws/tun`.
    pub server_address: String,
    /// Optional TLS SNI override (defaults to the URL host).
    #[serde(default)]
    pub sni_hostname: Option<String>,
    /// Pinned server identity (`ik:1:<base32>`). `None` = TOFU capture mode:
    /// the pin is captured on the first successful connection.
    #[serde(default)]
    pub server_identity_pin: Option<String>,
    /// DNS servers advertised through the tunnel (informational; the local
    /// DNS proxy resolves via DoH through the tunnel by default).
    #[serde(default = "default_dns")]
    pub dns_servers: Vec<String>,
    /// TUN MTU (default 1420, same as the macOS app).
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Ad/tracker blocking at the DNS layer. Always on, like the macOS app.
    #[serde(default = "default_true")]
    pub block_ads: bool,
    /// Split-tunnel master toggle (bypass lists + builtin country data).
    #[serde(default)]
    pub split_tunnel_enabled: bool,
    /// Builtin bypass countries (e.g. `IR`, `CN`) — traffic to these CIDR
    /// ranges bypasses the tunnel via the original gateway.
    #[serde(default)]
    pub builtin_bypass_countries: Vec<String>,
    /// Extra bypass networks in CIDR notation.
    #[serde(default)]
    pub bypass_networks: Vec<String>,
    /// Domains whose traffic must stay inside the tunnel even when a bypass
    /// rule would otherwise match (e.g. a bypassed-country bank that is
    /// blocked from your IP).
    #[serde(default)]
    pub tunnel_domains: Vec<String>,
    /// Domains routed outside the tunnel at the DNS layer.
    #[serde(default)]
    pub bypass_domains: Vec<String>,
    /// Marked as the default profile (auto-connect target).
    #[serde(default)]
    pub is_default: bool,
    /// Creation timestamp (RFC 3339).
    #[serde(default)]
    pub created_at: String,
}

fn default_dns() -> Vec<String> {
    vec!["1.1.1.1".into(), "8.8.8.8".into()]
}

fn default_mtu() -> u16 {
    1420
}

fn default_true() -> bool {
    true
}

impl Profile {
    pub fn new(name: &str) -> Self {
        Self {
            slug: slugify(name),
            name: name.to_string(),
            server_address: String::new(),
            sni_hostname: None,
            server_identity_pin: None,
            dns_servers: default_dns(),
            mtu: default_mtu(),
            block_ads: true,
            split_tunnel_enabled: false,
            builtin_bypass_countries: Vec::new(),
            bypass_networks: Vec::new(),
            tunnel_domains: Vec::new(),
            bypass_domains: Vec::new(),
            is_default: false,
            created_at: chrono::Local::now().to_rfc3339(),
        }
    }

    pub fn dir(&self) -> PathBuf {
        paths::profile_dir(&self.slug)
    }

    pub fn identity_path(&self) -> PathBuf {
        self.dir().join("identity.key")
    }

    pub fn prekey_path(&self) -> PathBuf {
        self.dir().join("prekey-bundle.json")
    }

    pub fn has_identity(&self) -> bool {
        self.identity_path().is_file()
    }

    pub fn has_prekey(&self) -> bool {
        self.prekey_path().is_file()
    }

    /// Basic validation before a connection attempt.
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            bail!("Profile name is empty");
        }
        let addr = self.server_address.trim();
        if !(addr.starts_with("wss://") || addr.starts_with("ws://")) {
            bail!("Server address must start with wss:// (or ws:// for testing)");
        }
        if !self.has_identity() {
            bail!("No identity key — generate or import one first");
        }
        if !self.has_prekey() {
            bail!("No server prekey bundle — import prekey-bundle.json first");
        }
        if let Some(pin) = &self.server_identity_pin {
            rvpn_core::identity_pin::parse_pin(pin)
                .map_err(|e| anyhow::anyhow!("Invalid server pin: {e}"))?;
        }
        Ok(())
    }

    /// Export as `.rvpn` JSON. `include_identity` embeds the private key
    /// (sensitive!); the TOFU pin is always carried so the recipient
    /// inherits server trust.
    pub fn export(&self, include_identity: bool) -> Result<String> {
        use base64::Engine;
        let identity_b64 = if include_identity {
            let bytes = std::fs::read(self.identity_path())
                .context("Failed to read identity key for export")?;
            Some(base64::engine::general_purpose::STANDARD.encode(bytes))
        } else {
            None
        };
        let prekey = std::fs::read_to_string(self.prekey_path())
            .context("Failed to read prekey bundle for export")?;

        let doc = ProfileExport {
            format: "rvpn-profile".into(),
            version: 1,
            profile: self.clone(),
            prekey_bundle: prekey,
            identity_key: identity_b64,
        };
        Ok(serde_json::to_string_pretty(&doc)?)
    }

    /// Ensure the slug is unique among `existing` (appends `-2`, `-3`, …).
    pub fn ensure_unique_slug(&mut self, existing: &[Profile]) {
        let taken: Vec<&str> = existing.iter().map(|p| p.slug.as_str()).collect();
        if !taken.contains(&self.slug.as_str()) {
            return;
        }
        for n in 2.. {
            let candidate = format!("{}-{n}", self.slug);
            if !taken.contains(&candidate.as_str()) {
                self.slug = candidate;
                return;
            }
        }
    }
}

/// `.rvpn` import/export document.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProfileExport {
    pub format: String,
    pub version: u32,
    pub profile: Profile,
    /// Raw prekey-bundle.json content.
    pub prekey_bundle: String,
    /// Base64 identity key file content (only when exported with it).
    #[serde(default)]
    pub identity_key: Option<String>,
}

/// Filesystem-backed profile store.
pub struct ProfileStore;

impl ProfileStore {
    pub fn load() -> Result<Vec<Profile>> {
        let path = paths::profiles_file();
        if !path.is_file() {
            return Ok(Vec::new());
        }
        let raw = std::fs::read_to_string(&path).context("Failed to read profiles.json")?;
        let profiles: Vec<Profile> =
            serde_json::from_str(&raw).context("profiles.json is corrupted")?;
        Ok(profiles
            .into_iter()
            .take(MAX_PROFILES)
            .collect())
    }

    pub fn save(profiles: &[Profile]) -> Result<()> {
        let path = paths::profiles_file();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_string_pretty(profiles)?)?;
        Ok(())
    }

    /// Write a profile's material (identity / prekey) into its directory.
    pub fn write_identity(slug: &str, content: &str) -> Result<PathBuf> {
        let dir = paths::profile_dir(slug);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("identity.key");
        std::fs::write(&path, content)?;
        Ok(path)
    }

    pub fn write_prekey(slug: &str, content: &str) -> Result<PathBuf> {
        let dir = paths::profile_dir(slug);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("prekey-bundle.json");
        std::fs::write(&path, content)?;
        Ok(path)
    }

    pub fn delete(profile: &Profile) -> Result<()> {
        let dir = profile.dir();
        if dir.is_dir() {
            std::fs::remove_dir_all(&dir).with_context(|| {
                format!("Failed to remove profile directory {}", dir.display())
            })?;
        }
        Ok(())
    }

    /// Import a `.rvpn` document; returns the stored profile.
    ///
    /// When the export carries no identity key (the default — keys are
    /// per-device), a fresh identity is generated automatically so the
    /// recipient only has to press Connect.
    pub fn import(doc: &str, existing: &[Profile]) -> Result<Profile> {
        let export: ProfileExport =
            serde_json::from_str(doc).context("Not a valid .rvpn profile file")?;
        if export.format != "rvpn-profile" {
            bail!("Unrecognized profile format: {}", export.format);
        }
        let mut profile = export.profile;
        profile.ensure_unique_slug(existing);
        // Validate the prekey bundle parses before storing it.
        serde_json::from_str::<rvpn_core::crypto::X3DHPublicBundle>(&export.prekey_bundle)
            .context("Prekey bundle inside the profile is invalid")?;
        Self::write_prekey(&profile.slug, &export.prekey_bundle)?;

        let dir = profile.dir();
        match &export.identity_key {
            Some(identity_b64) => {
                use base64::Engine;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(identity_b64)
                    .context("Identity key inside the profile is not valid base64")?;
                let text = String::from_utf8(bytes)
                    .context("Identity key inside the profile is not valid UTF-8")?;
                let path = Self::write_identity(&profile.slug, &text)?;
                // Validate by loading; drop the file again if it is garbage.
                if let Err(e) = rvpn_core::crypto::IdentityKey::load(&path) {
                    let _ = std::fs::remove_file(&path);
                    bail!("Identity key inside the profile is invalid: {e}");
                }
            }
            None => {
                if !dir.join("identity.key").is_file() {
                    crate::identity::generate_identity(&dir.join("identity.key"))
                        .context("failed to generate a fresh identity for the imported profile")?;
                }
            }
        }
        Ok(profile)
    }
}

/// Filesystem-safe slug from a display name (ASCII lowercase + dashes).
pub fn slugify(name: &str) -> String {
    let mut out = String::new();
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if (ch == ' ' || ch == '_' || ch == '-') && !out.ends_with('-') {
            out.push('-');
        }
    }
    let slug = out.trim_matches('-').to_string();
    if slug.is_empty() {
        "profile".into()
    } else {
        slug.chars().take(48).collect()
    }
}

/// Connection-relevant settings persisted next to profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    /// Auto-connect the default profile at launch.
    #[serde(default)]
    pub auto_connect: bool,
    /// Start with the app (HKCU Run key).
    #[serde(default)]
    pub launch_at_startup: bool,
    /// Hide the window at launch (tray only).
    #[serde(default)]
    pub start_minimized: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            auto_connect: false,
            launch_at_startup: false,
            start_minimized: false,
        }
    }
}

impl AppSettings {
    pub fn load_from_disk() -> Self {
        std::fs::read_to_string(paths::settings_file())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.server_address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugify_basic() {
        assert_eq!(slugify("My Server #1"), "my-server-1");
        assert_eq!(slugify("  تهران  "), "profile");
        assert_eq!(slugify("A_B"), "a-b");
    }

    #[test]
    fn profile_json_roundtrip() {
        let mut p = Profile::new("Test");
        p.server_address = "wss://example.com:443/api/v1/ws/tun".into();
        p.server_identity_pin = Some("ik:1:ABCDEFGHIJKLMNOP234567".into());
        let json = serde_json::to_string(&p).unwrap();
        let back: Profile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.slug, p.slug);
        assert_eq!(back.mtu, 1420);
        assert_eq!(back.dns_servers, vec!["1.1.1.1", "8.8.8.8"]);
        assert!(back.block_ads);
    }

    #[test]
    fn unique_slug_appends_counter() {
        let a = Profile::new("Work");
        let mut b = Profile::new("Work");
        b.ensure_unique_slug(&[a.clone()]);
        assert_eq!(b.slug, "work-2");
    }

    #[test]
    fn validate_requires_https_url() {
        let mut p = Profile::new("X");
        p.server_address = "example.com".into();
        assert!(p.validate().is_err());
    }
}
