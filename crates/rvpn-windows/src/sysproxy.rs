//! Windows system-proxy wiring for SOCKS5 mode.
//!
//! When the proxy engine connects we point the WinINET system proxy at the
//! local SOCKS5 listener (Chrome/Edge/Firefox-with-system-settings follow
//! it), and restore the user's previous configuration on disconnect. The
//! previous values are also mirrored to disk so a crash can't leave the
//! machine hijacked — the next app start sweeps the leftover state.

use anyhow::{Context, Result};
use winreg::enums::{HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE};
use winreg::RegKey;

const INET_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const BACKUP_FILE: &str = "sysproxy-backup.json";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct ProxyBackup {
    pub enable: u32,
    pub server: Option<String>,
    pub override_list: Option<String>,
}

fn inet_key(access: u32) -> Result<RegKey> {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INET_KEY, access)
        .context("Internet Settings key unavailable")
}

fn backup_path() -> std::path::PathBuf {
    crate::paths::app_data_dir().join(BACKUP_FILE)
}

/// Point the system proxy at `socks=host:port` and remember what was there.
pub fn set_system_proxy(host: &str, port: u16) -> Result<()> {
    let key = inet_key(KEY_QUERY_VALUE).context("cannot read proxy settings")?;
    let backup = ProxyBackup {
        enable: key.get_value::<u32, _>("ProxyEnable").unwrap_or(0),
        server: key.get_value::<String, _>("ProxyServer").ok(),
        override_list: key.get_value::<String, _>("ProxyOverride").ok(),
    };
    std::fs::write(backup_path(), serde_json::to_vec(&backup)?)
        .context("cannot persist the proxy backup")?;

    let key = inet_key(KEY_SET_VALUE).context("cannot write proxy settings")?;
    key.set_value("ProxyEnable", &1u32)?;
    key.set_value("ProxyServer", &format!("socks={host}:{port}"))?;
    // Keep loopback and LAN traffic out of the proxy (it can't reach itself
    // through itself); everything else is decided by the engine's rules.
    key.set_value(
        "ProxyOverride",
        &"localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.2*;172.30.*;172.31.*;192.168.*;<local>",
    )?;
    notify_wininet();
    tracing::info!(host, port, "system proxy set");
    Ok(())
}

/// Restore whatever `set_system_proxy` replaced.
pub fn restore_system_proxy() {
    let Ok(raw) = std::fs::read(backup_path()) else {
        return; // nothing of ours set
    };
    let _ = std::fs::remove_file(backup_path());
    let Ok(backup) = serde_json::from_slice::<ProxyBackup>(&raw) else {
        return;
    };
    if let Ok(key) = inet_key(KEY_SET_VALUE) {
        let _ = key.set_value("ProxyEnable", &backup.enable);
        match &backup.server {
            Some(server) => {
                let _ = key.set_value("ProxyServer", server);
            }
            None => {
                let _ = key.delete_value("ProxyServer");
            }
        }
        match &backup.override_list {
            Some(list) => {
                let _ = key.set_value("ProxyOverride", list);
            }
            None => {
                let _ = key.delete_value("ProxyOverride");
            }
        }
        notify_wininet();
        tracing::info!("system proxy restored");
    }
}

/// Startup self-healing: if a previous run died while the system proxy was
/// ours, put the user's settings back.
pub fn sweep_stale_system_proxy() {
    restore_system_proxy();
}

/// Tell WinINET consumers (browsers) the settings changed — without this a
/// logoff/logon would be needed.
fn notify_wininet() {
    const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
    const INTERNET_OPTION_REFRESH: u32 = 37;
    unsafe {
        windows_sys::Win32::Networking::WinInet::InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null(),
            0,
        );
        windows_sys::Win32::Networking::WinInet::InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null(),
            0,
        );
    }
}
