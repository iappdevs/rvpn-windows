//! One-shot profile bootstrap: generates a fresh client identity, copies
//! the server's prekey bundle, and writes the profile index — so the GUI
//! opens ready-to-connect.
//!
//! ```text
//! cargo run --release --no-default-features --example setup_profile -- \
//!     --name "My Server" --server wss://dl.99aa.ir:8443/api/v1/ws/tun \
//!     --prekey prekey-bundle.json --default
//! ```

use std::path::PathBuf;

use rvpn_windows::{identity, paths, profile::{Profile, ProfileStore}};

fn main() -> anyhow::Result<()> {
    let mut name = String::new();
    let mut server = String::new();
    let mut prekey_path: Option<PathBuf> = None;
    let mut make_default = false;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--name" => name = it.next().cloned().unwrap_or_default(),
            "--server" => server = it.next().cloned().unwrap_or_default(),
            "--prekey" => prekey_path = it.next().map(PathBuf::from),
            "--default" => make_default = true,
            other => anyhow::bail!("unknown argument: {other}"),
        }
    }

    anyhow::ensure!(!name.is_empty() && !server.is_empty(), "--name and --server are required");
    let prekey_path = prekey_path
        .ok_or_else(|| anyhow::anyhow!("--prekey <path to prekey-bundle.json> is required"))?;
    let prekey = std::fs::read_to_string(&prekey_path)?;
    let pin = identity::validate_prekey_text(&prekey)?;

    let mut profile = Profile::new(&name);
    profile.server_address = server;
    profile.is_default = make_default;

    let mut profiles = ProfileStore::load().unwrap_or_default();
    if make_default {
        for p in profiles.iter_mut() {
            p.is_default = false;
        }
    }
    profile.ensure_unique_slug(&profiles);

    let dir = paths::profile_dir(&profile.slug);
    std::fs::create_dir_all(&dir)?;
    identity::generate_identity(&dir.join("identity.key"))?;
    std::fs::write(dir.join("prekey-bundle.json"), &prekey)?;

    profiles.push(profile.clone());
    ProfileStore::save(&profiles)?;

    println!("profile '{}' ready ({})", profile.name, profile.slug);
    println!("  server pin: {pin}");
    Ok(())
}
