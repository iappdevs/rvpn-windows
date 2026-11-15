//! Windows system-proxy wiring for the mixed HTTP/SOCKS inbound.
//!
//! When the proxy engine connects we point the WinINET system proxy at the
//! local mixed listener (Chrome/Edge/Firefox-with-system-settings follow
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
    #[serde(default)]
    pub auto_config_url: Option<String>,
    #[serde(default)]
    pub connection_flags: Option<u32>,
    #[serde(default)]
    pub owner_token: Option<String>,
}

fn inet_key(access: u32) -> Result<RegKey> {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INET_KEY, access)
        .context("Internet Settings key unavailable")
}

fn backup_path() -> std::path::PathBuf {
    crate::paths::app_data_dir().join(BACKUP_FILE)
}

/// Point HTTP and HTTPS at the mixed inbound, like v2rayN's default Windows
/// proxy string. CONNECT retains domains for rules; WinINET SOCKS4 loses them.
pub fn set_system_proxy(host: &str, port: u16) -> Result<()> {
    let _lock = ProxyLock::acquire()?;
    anyhow::ensure!(
        !backup_path().exists(),
        "Previous proxy backup is still pending restoration"
    );
    let key = inet_key(KEY_QUERY_VALUE).context("cannot read proxy settings")?;
    let mut backup = ProxyBackup {
        enable: key.get_value::<u32, _>("ProxyEnable").unwrap_or(0),
        server: key.get_value::<String, _>("ProxyServer").ok(),
        override_list: key.get_value::<String, _>("ProxyOverride").ok(),
        auto_config_url: key.get_value::<String, _>("AutoConfigURL").ok(),
        connection_flags: Some(connection_flags()?),
        owner_token: Some(format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        )),
    };
    // A dead RVPN listener left by an older build is not a useful state to
    // restore. A different existing proxy/PAC remains exactly as it was.
    normalize_previous_listener(&mut backup, &proxy_server(host, port));
    std::fs::write(backup_path(), serde_json::to_vec(&backup)?)
        .context("cannot persist the proxy backup")?;

    let result = start_watchdog(backup.owner_token.as_deref().unwrap())
        .and_then(|_| apply_connection(3, &proxy_server(host, port), "localhost;127.*;[::1]", ""));
    if let Err(error) = result {
        restore_owned(None);
        return Err(error);
    }
    notify_wininet();
    tracing::info!(host, port, "system proxy set");
    Ok(())
}

pub fn proxy_server(host: &str, port: u16) -> String {
    // v2rayN's default Windows proxy string: one HTTP proxy for all schemes.
    format!("{host}:{port}")
}

/// Restore whatever `set_system_proxy` replaced.
pub fn restore_system_proxy() {
    match ProxyLock::acquire() {
        Ok(_lock) => restore_owned(None),
        Err(error) => tracing::error!(%error, "Cannot acquire system proxy cleanup lock"),
    }
}

fn restore_owned(owner: Option<&str>) {
    let Ok(raw) = std::fs::read(backup_path()) else {
        return; // nothing of ours set
    };
    let Ok(backup) = serde_json::from_slice::<ProxyBackup>(&raw) else {
        return;
    };
    if !owns_backup(&backup, owner) {
        return;
    }
    let result = (|| -> Result<()> {
        if let Some(flags) = backup.connection_flags {
            apply_connection(
                flags,
                backup.server.as_deref().unwrap_or(""),
                backup.override_list.as_deref().unwrap_or(""),
                backup.auto_config_url.as_deref().unwrap_or(""),
            )?;
        }
        let key = inet_key(KEY_SET_VALUE)?;
        key.set_value("ProxyEnable", &backup.enable)?;
        match &backup.server {
            Some(server) => {
                key.set_value("ProxyServer", server)?;
            }
            None => {
                delete_optional(&key, "ProxyServer")?;
            }
        }
        match &backup.override_list {
            Some(list) => {
                key.set_value("ProxyOverride", list)?;
            }
            None => {
                delete_optional(&key, "ProxyOverride")?;
            }
        }
        // Older backup documents never changed PAC settings. Leave them alone.
        if backup.connection_flags.is_some() {
            match &backup.auto_config_url {
                Some(url) => key.set_value("AutoConfigURL", url)?,
                None => {
                    delete_optional(&key, "AutoConfigURL")?;
                }
            }
        }
        notify_wininet();
        tracing::info!("system proxy restored");
        Ok(())
    })();
    if result.is_ok() {
        let _ = std::fs::remove_file(backup_path());
    } else if let Err(e) = result {
        tracing::warn!(error = %e, "could not restore system proxy; backup retained for next startup");
    }
}

fn owns_backup(backup: &ProxyBackup, owner: Option<&str>) -> bool {
    owner.is_none() || backup.owner_token.as_deref() == owner
}

/// A separate copy of this same executable survives a killed GUI process.
/// It restores only its own connection's backup, never a newer session's.
fn start_watchdog(token: &str) -> Result<()> {
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::Threading::*;
    let ready_name = ready_event_name(token);
    let ready = Handle(unsafe { CreateEventW(std::ptr::null(), 1, 0, ready_name.as_ptr()) });
    anyhow::ensure!(!ready.0.is_null(), "Cannot create proxy cleanup handshake");
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args(["--proxy-watchdog", &std::process::id().to_string(), token])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("Cannot start system proxy cleanup helper")?;
    if unsafe { WaitForSingleObject(ready.0, 10_000) }
        != windows_sys::Win32::Foundation::WAIT_OBJECT_0
    {
        let _ = child.kill();
        let _ = child.wait();
        anyhow::bail!("System proxy cleanup helper did not become ready");
    }
    Ok(())
}

/// Must run before the GUI, single-instance handling or profile loading.
pub fn run_watchdog_from_args() -> bool {
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some("--proxy-watchdog") {
        return false;
    }
    let result = (|| -> Result<()> {
        anyhow::ensure!(args.len() == 4, "Invalid cleanup helper arguments");
        let pid: u32 = args[2].parse()?;
        let token = &args[3];
        anyhow::ensure!(
            token.len() < 100 && token.bytes().all(|b| b.is_ascii_digit() || b == b'-'),
            "Invalid cleanup owner"
        );
        watch_parent(pid, token)
    })();
    if let Err(error) = result {
        eprintln!("Proxy cleanup helper: {error:#}");
    }
    true
}

fn watch_parent(pid: u32, token: &str) -> Result<()> {
    watch_process(
        pid,
        || {
            use windows_sys::Win32::System::Threading::*;
            let name = ready_event_name(token);
            let ready = Handle(unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, name.as_ptr()) });
            if !ready.0.is_null() {
                unsafe {
                    SetEvent(ready.0);
                }
            }
        },
        |exited| {
            let _lock = ProxyLock::acquire()?;
            if exited {
                restore_owned(Some(token));
                return Ok(true);
            }
            let still_owned = std::fs::read(backup_path())
                .ok()
                .and_then(|raw| serde_json::from_slice::<ProxyBackup>(&raw).ok())
                .is_some_and(|backup| owns_backup(&backup, Some(token)));
            Ok(!still_owned)
        },
    )
}

fn watch_process(
    pid: u32,
    ready: impl FnOnce(),
    mut tick: impl FnMut(bool) -> Result<bool>,
) -> Result<()> {
    use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::*;
    let parent = Handle(unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) });
    if parent.0.is_null() {
        anyhow::ensure!(
            std::io::Error::last_os_error().raw_os_error() == Some(87),
            "Cannot watch the proxy owner process"
        );
    }
    ready();
    loop {
        let status = if parent.0.is_null() {
            WAIT_OBJECT_0
        } else {
            unsafe { WaitForSingleObject(parent.0, 500) }
        };
        anyhow::ensure!(
            status == WAIT_OBJECT_0 || status == WAIT_TIMEOUT,
            "Cannot wait for the proxy owner process"
        );
        if tick(status == WAIT_OBJECT_0)? {
            return Ok(());
        }
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn ready_event_name(token: &str) -> Vec<u16> {
    wide(&format!("Local\\rvpn-proxy-ready-{token}"))
}
fn normalize_previous_listener(backup: &mut ProxyBackup, listener: &str) {
    if backup.server.as_deref() == Some(listener) {
        backup.enable = 0;
        if let Some(flags) = backup.connection_flags.as_mut() {
            *flags = (*flags & !2) | 1;
        }
    }
}
struct Handle(windows_sys::Win32::Foundation::HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}
struct ProxyLock(Handle);
impl ProxyLock {
    fn acquire() -> Result<Self> {
        use windows_sys::Win32::{
            Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0},
            System::Threading::*,
        };
        let name = wide("Local\\rvpn-windows-system-proxy");
        let handle = Handle(unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) });
        anyhow::ensure!(!handle.0.is_null(), "Cannot create system proxy lock");
        let status = unsafe { WaitForSingleObject(handle.0, 15_000) };
        anyhow::ensure!(
            status == WAIT_OBJECT_0 || status == WAIT_ABANDONED,
            "System proxy lock timed out"
        );
        Ok(Self(handle))
    }
}
impl Drop for ProxyLock {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::System::Threading::ReleaseMutex(self.0 .0);
        }
    }
}

fn delete_optional(key: &RegKey, name: &str) -> std::io::Result<()> {
    match key.delete_value(name) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

/// v2rayN uses the per-connection WinINET API: selecting a manual proxy
/// must disable PAC/WPAD, and teardown must restore their previous flags.
fn connection_flags() -> Result<u32> {
    use windows_sys::Win32::Networking::WinInet::*;
    let mut option = INTERNET_PER_CONN_OPTIONW {
        dwOption: INTERNET_PER_CONN_FLAGS_UI,
        Value: INTERNET_PER_CONN_OPTIONW_0 { dwValue: 0 },
    };
    let mut list = connection_list(std::slice::from_mut(&mut option));
    let mut size = std::mem::size_of_val(&list) as u32;
    unsafe {
        if InternetQueryOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            &mut list as *mut _ as *mut _,
            &mut size,
        ) == 0
        {
            option.dwOption = INTERNET_PER_CONN_FLAGS;
            if InternetQueryOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_PER_CONNECTION_OPTION,
                &mut list as *mut _ as *mut _,
                &mut size,
            ) == 0
            {
                return Err(std::io::Error::last_os_error())
                    .context("Cannot capture WinINET proxy flags");
            }
        }
        Ok(option.Value.dwValue)
    }
}

fn connection_list(
    options: &mut [windows_sys::Win32::Networking::WinInet::INTERNET_PER_CONN_OPTIONW],
) -> windows_sys::Win32::Networking::WinInet::INTERNET_PER_CONN_OPTION_LISTW {
    windows_sys::Win32::Networking::WinInet::INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: std::mem::size_of::<
            windows_sys::Win32::Networking::WinInet::INTERNET_PER_CONN_OPTION_LISTW,
        >() as u32,
        pszConnection: std::ptr::null_mut(),
        dwOptionCount: options.len() as u32,
        dwOptionError: 0,
        pOptions: options.as_mut_ptr(),
    }
}

fn apply_connection(flags: u32, server: &str, bypass: &str, pac: &str) -> Result<()> {
    use windows_sys::Win32::Networking::WinInet::*;
    let mut strings: Vec<Vec<u16>> = [server, bypass, pac]
        .iter()
        .map(|s| s.encode_utf16().chain(Some(0)).collect())
        .collect();
    let mut options = vec![INTERNET_PER_CONN_OPTIONW {
        dwOption: INTERNET_PER_CONN_FLAGS,
        Value: INTERNET_PER_CONN_OPTIONW_0 { dwValue: flags },
    }];
    for (kind, value) in [
        INTERNET_PER_CONN_PROXY_SERVER,
        INTERNET_PER_CONN_PROXY_BYPASS,
        INTERNET_PER_CONN_AUTOCONFIG_URL,
    ]
    .into_iter()
    .zip(strings.iter_mut())
    {
        options.push(INTERNET_PER_CONN_OPTIONW {
            dwOption: kind,
            Value: INTERNET_PER_CONN_OPTIONW_0 {
                pszValue: value.as_mut_ptr(),
            },
        });
    }
    let mut list = connection_list(&mut options);
    // All pointers remain live until this synchronous call returns.
    unsafe {
        if InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            &mut list as *mut _ as *mut _,
            std::mem::size_of_val(&list) as u32,
        ) == 0
        {
            return Err(std::io::Error::last_os_error())
                .context("Cannot apply WinINET proxy settings");
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::Duration,
    };

    #[test]
    fn watchdog_restoration_cannot_claim_a_newer_session_or_legacy_backup() {
        let backup = ProxyBackup {
            owner_token: Some("new-owner".into()),
            ..Default::default()
        };
        assert!(!owns_backup(&backup, Some("old-owner")));
        assert!(owns_backup(&backup, Some("new-owner")));
        assert!(owns_backup(&backup, None));
        assert!(!owns_backup(&ProxyBackup::default(), Some("old-owner")));
    }

    #[test]
    fn watchdog_ready_handshake_uses_the_same_windows_event() {
        use windows_sys::Win32::System::Threading::*;
        let token = format!("test-{}", std::process::id());
        let name = ready_event_name(&token);
        let event = Handle(unsafe { CreateEventW(std::ptr::null(), 1, 0, name.as_ptr()) });
        assert!(!event.0.is_null());
        let signal =
            Handle(unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, ready_event_name(&token).as_ptr()) });
        assert!(!signal.0.is_null());
        unsafe {
            SetEvent(signal.0);
        }
        assert_eq!(
            unsafe { WaitForSingleObject(event.0, 1000) },
            windows_sys::Win32::Foundation::WAIT_OBJECT_0
        );
    }

    #[test]
    fn previous_dead_listener_is_disabled_but_other_proxies_are_preserved() {
        let mut own = ProxyBackup {
            enable: 1,
            server: Some("127.0.0.1:1080".into()),
            connection_flags: Some(3),
            ..Default::default()
        };
        normalize_previous_listener(&mut own, "127.0.0.1:1080");
        assert_eq!(own.enable, 0);
        assert_eq!(own.connection_flags, Some(1));
        let mut other = ProxyBackup {
            enable: 1,
            server: Some("127.0.0.1:9090".into()),
            connection_flags: Some(13),
            ..Default::default()
        };
        normalize_previous_listener(&mut other, "127.0.0.1:1080");
        assert_eq!(other.enable, 1);
        assert_eq!(other.connection_flags, Some(13));
    }

    #[test]
    fn process_watch_survives_forced_exit_and_notifies_after_death() {
        // A harmless child, not RVPN: no registry or native proxy changes.
        use std::os::windows::process::CommandExt;
        let mut child = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 30",
            ])
            .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let id = child.id();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let restored = Arc::new(AtomicBool::new(false));
        let observed = restored.clone();
        let watcher = std::thread::spawn(move || {
            watch_process(
                id,
                || {
                    ready_tx.send(()).unwrap();
                },
                |exited| {
                    if exited {
                        observed.store(true, Ordering::SeqCst);
                    }
                    Ok(exited)
                },
            )
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(!restored.load(Ordering::SeqCst));
        child.kill().unwrap();
        child.wait().unwrap();
        watcher.join().unwrap().unwrap();
        assert!(restored.load(Ordering::SeqCst));
    }
}
