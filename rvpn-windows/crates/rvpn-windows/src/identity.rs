//! Identity key management (generate / import / validate) and prekey
//! bundle validation, backed by `rvpn-core` primitives.

use anyhow::Result;
use std::path::Path;

/// Generate a fresh identity and save it to `path` (the engine's own
/// `IdentityKey::save` writes the portable R-VPN-IDENTITY-v1 format that
/// every rVPN client loads).
pub fn generate_identity(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let key = rvpn_core::crypto::IdentityKey::generate();
    key.save(path)
        .map_err(|e| anyhow::anyhow!("failed to save identity: {}", e))
}

/// Validate an identity key file by loading it.
pub fn validate_identity_file(path: &Path) -> Result<()> {
    rvpn_core::crypto::IdentityKey::load(path)
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("invalid identity key: {}", e))
}

/// Validate prekey-bundle JSON text and return the server's identity pin
/// (`ik:1:<base32>`) computed from the bundle's identity key.
pub fn validate_prekey_text(text: &str) -> Result<String> {
    let bundle: rvpn_core::crypto::X3DHPublicBundle = serde_json::from_str(text)
        .map_err(|e| anyhow::anyhow!("not a valid prekey bundle: {e}"))?;
    let pin = rvpn_core::identity_pin::encode_identity_pin(&bundle.identity_key)
        .map_err(|e| anyhow::anyhow!("failed to compute server pin: {e}"))?;
    Ok(pin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identity_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        generate_identity(&path).unwrap();
        validate_identity_file(&path).unwrap();
    }
}
