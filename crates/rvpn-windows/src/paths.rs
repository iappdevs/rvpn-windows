//! Application paths (all under `%APPDATA%` / `%LOCALAPPDATA%`).

use std::path::PathBuf;

/// `%APPDATA%\rvpn-windows` — profiles, identities, prekey bundles, settings.
pub fn app_data_dir() -> PathBuf {
    let base = std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join("rvpn-windows")
}

/// `%LOCALAPPDATA%\rvpn-windows\logs`
pub fn log_dir() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join("rvpn-windows").join("logs")
}

/// Per-profile directory: `<app_data>/profiles/<slug>/`
pub fn profile_dir(slug: &str) -> PathBuf {
    app_data_dir().join("profiles").join(slug)
}

/// Profiles index: `<app_data>/profiles.json`
pub fn profiles_file() -> PathBuf {
    app_data_dir().join("profiles.json")
}

/// App settings: `<app_data>/settings.json`
pub fn settings_file() -> PathBuf {
    app_data_dir().join("settings.json")
}

/// Ensure the base directories exist. Called once at startup.
pub fn ensure_dirs() -> std::io::Result<()> {
    std::fs::create_dir_all(app_data_dir())?;
    std::fs::create_dir_all(log_dir())?;
    Ok(())
}
