//! Self-updater: checks the GitHub releases of `iappdevs/rvpn-windows`,
//! downloads the newest `*-win64.zip`, swaps it in next to the running
//! executable, and relaunches the app.
//!
//! Network access rides PowerShell's `Invoke-*` cmdlets on purpose: they
//! honour the Windows system proxy, so when the app is connected (system
//! proxy or full tunnel) the update traffic flows through the tunnel too.
//!
//! Replacing a running exe: Windows locks a running image against writes
//! but not against RENAME — the current exe is moved aside as
//! `<name>.exe.old`, the new one is copied into place, and the old file is
//! swept on the next startup (`cleanup_old`).

use std::path::{Path, PathBuf};

use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

const RELEASES_API: &str = "https://api.github.com/repos/iappdevs/rvpn-windows/releases/latest";
pub const APP_EXE_NAME: &str = "rvpn-windows.exe";
pub const WINTUN_NAME: &str = "wintun.dll";

#[derive(Debug, Clone, Deserialize)]
pub struct ReleaseInfo {
    #[serde(rename = "tag_name")]
    pub tag: String,
    #[serde(default)]
    pub body: String,
    /// Download URL of the `*-win64.zip` asset.
    #[serde(default)]
    pub url: String,
}

impl ReleaseInfo {
    pub fn version(&self) -> Option<(u64, u64, u64)> {
        parse_version(&self.tag)
    }
}

/// "v0.1.2" / "0.1.2" → (0, 1, 2)
pub fn parse_version(tag: &str) -> Option<(u64, u64, u64)> {
    let nums: Vec<&str> = tag.trim_start_matches('v').trim().split('.').collect();
    if nums.len() != 3 {
        return None;
    }
    Some((nums[0].parse().ok()?, nums[1].parse().ok()?, nums[2].parse().ok()?))
}

pub fn is_newer(tag: &str, current: &str) -> bool {
    match (parse_version(tag), parse_version(current)) {
        (Some(t), Some(c)) => t > c,
        _ => false,
    }
}

/// Query the latest release (tag + notes + zip URL) via PowerShell, so the
/// request follows the Windows/system proxy (i.e. rides the tunnel when
/// connected). ~1-2s; call from a background thread.
pub fn fetch_latest() -> Result<ReleaseInfo> {
    let script = format!(
        "$ProgressPreference='SilentlyContinue'; \
         (Invoke-RestMethod '{RELEASES_API}' -TimeoutSec 20) \
         | Select-Object tag_name, body, \
             @{{n='url';e={{($_.assets | Where-Object name -like '*win64.zip' | \
               Select-Object -First 1).browser_download_url}}}} \
         | ConvertTo-Json -Compress"
    );
    let out = run_ps(&script)?;
    let info: ReleaseInfo =
        serde_json::from_str(out.trim()).context("could not parse the release feed")?;
    if info.url.is_empty() {
        bail!("latest release has no *-win64.zip asset");
    }
    Ok(info)
}

/// Download the release zip to `dest` (system-proxy aware).
pub fn download(url: &str, dest: &Path) -> Result<()> {
    let script = format!(
        "$ProgressPreference='SilentlyContinue'; \
         Invoke-WebRequest '{url}' -OutFile '{}' -TimeoutSec 900",
        dest.display()
    );
    run_ps(&script)?;
    if !dest.is_file() {
        bail!("download finished but the file is missing");
    }
    Ok(())
}

/// Extract `zip` into `dest_dir` (created).
pub fn extract(zip: &Path, dest_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dest_dir)?;
    let script = format!(
        "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
        zip.display(),
        dest_dir.display()
    );
    run_ps(&script)?;
    Ok(())
}

/// Swap the freshly extracted build into `exe_dir`:
/// running exe (and wintun.dll) are renamed to `*.old`, new files copied in.
/// Returns the path of the NEW executable.
pub fn install_from(extracted: &Path, exe_dir: &Path) -> Result<PathBuf> {
    let new_exe = find_file(extracted, APP_EXE_NAME).context("zip has no rvpn-windows.exe")?;
    let target_exe = exe_dir.join(APP_EXE_NAME);

    move_aside(&target_exe);
    std::fs::copy(&new_exe, &target_exe)
        .with_context(|| format!("copying {} into place", target_exe.display()))?;

    if let Some(new_dll) = find_file(extracted, WINTUN_NAME) {
        let target_dll = exe_dir.join(WINTUN_NAME);
        move_aside(&target_dll);
        std::fs::copy(&new_dll, &target_dll).context("copying wintun.dll into place")?;
    }
    Ok(target_exe)
}

/// Full pipeline: download → extract → install. Returns the new exe path.
pub fn download_and_install(url: &str, exe_dir: &Path) -> Result<PathBuf> {
    let tmp = std::env::temp_dir().join(format!("rvpn-update-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).context("cannot create the update temp folder")?;
    let _guard = TempDirGuard(&tmp);
    let zip = tmp.join("update.zip");
    download(url, &zip)?;
    let dir = tmp.join("unzipped");
    extract(&zip, &dir)?;
    install_from(&dir, exe_dir)
}

/// Relaunch the given exe elevated (the app's manifest requires
/// Administrator, so a plain spawn would just bounce off UAC).
pub fn relaunch(exe: &Path) -> bool {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    let verb: Vec<u16> = "runas\0".encode_utf16().collect();
    let file: Vec<u16> = format!("{}\0", exe.display()).encode_utf16().collect();
    // SW_SHOW = 5
    let rc = unsafe { ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), file.as_ptr(), std::ptr::null(), std::ptr::null(), 5) };
    rc as usize > 32
}

/// Remove `*.old` leftovers from previous updates (call at startup).
pub fn cleanup_old() {
    let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)) else {
        return;
    };
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".old") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

fn move_aside(path: &Path) {
    // "<name>.exe.old" (not with_extension — that would REPLACE the suffix).
    let old = PathBuf::from(format!("{}.old", path.display()));
    let _ = std::fs::remove_file(&old);
    if path.exists() {
        // Rename works even for the running exe / loaded DLL.
        let _ = std::fs::rename(path, &old);
    }
}

fn find_file(root: &Path, name: &str) -> Option<PathBuf> {
    if root.is_file() && root.file_name()?.eq_ignore_ascii_case(name) {
        return Some(root.to_path_buf());
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.file_name().map(|f| f.eq_ignore_ascii_case(name)).unwrap_or(false) {
                return Some(p);
            }
        }
    }
    None
}

fn run_ps(script: &str) -> Result<String> {
    run_ps_with_timeout(script, Duration::from_secs(45))
}

/// Run PowerShell with a hard watchdog.
///
/// `-TimeoutSec` only bounds the HTTP request itself; on filtered networks
/// PowerShell can still hang for minutes inside proxy auto-discovery (WPAD)
/// or DNS before the request even starts, leaving the update check stuck on
/// "Checking for updates…" forever. The watchdog kills the process at the
/// deadline so the caller always gets an answer.
fn run_ps_with_timeout(script: &str, timeout: Duration) -> Result<String> {
    // Force UTF-8 on the piped stdout: with the OEM codepage, non-ASCII
    // characters in release notes turn into control bytes that break the
    // JSON parse downstream.
    let script = format!("[Console]::OutputEncoding=[Text.Encoding]::UTF8; {script}");
    let mut child = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn powershell")?;

    // Drain both pipes while the child runs. Left unread, a child that
    // writes more than a pipe buffer blocks on the write and never exits —
    // the poll below would then wait until the watchdog every time.
    fn drain<R: std::io::Read + Send + 'static>(mut pipe: R) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = std::io::Read::read_to_end(&mut pipe, &mut buf);
            buf
        })
    }
    let stdout = drain(child.stdout.take().context("stdout not piped")?);
    let stderr = drain(child.stderr.take().context("stderr not piped")?);

    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                bail!("powershell timed out after {}s", timeout.as_secs());
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    };
    let out = std::process::Output {
        status,
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    };
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        bail!("powershell failed: {}", if err.is_empty() { out.status.to_string() } else { err });
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

struct TempDirGuard<'a>(&'a Path);
impl Drop for TempDirGuard<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// More than any pipe buffer. Left unread, the child would block on the
    /// write and the poll would sit until the watchdog — which is what the
    /// first watchdog implementation did.
    #[test]
    fn large_powershell_output_does_not_deadlock() {
        let started = std::time::Instant::now();
        let out = run_ps_with_timeout(
            "[Console]::Write(('x' * 200000))",
            Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(out.matches('x').count(), 200_000);
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "took {:?} — the output was not drained while the child ran",
            started.elapsed()
        );
    }

    #[test]
    fn version_parsing_and_comparison() {
        assert_eq!(parse_version("v0.1.2"), Some((0, 1, 2)));
        assert_eq!(parse_version("0.10.0"), Some((0, 10, 0)));
        assert_eq!(parse_version("nonsense"), None);
        assert!(is_newer("v0.1.2", "0.1.1"));
        assert!(!is_newer("v0.1.2", "0.1.2"));
        assert!(!is_newer("v0.1.0", "0.1.2"));
        assert!(!is_newer("garbage", "0.1.2"));
    }

    #[test]
    fn install_swaps_files_and_keeps_old() {
        let dir = tempfile::tempdir().unwrap();
        let exe_dir = dir.path().join("app");
        let src = dir.path().join("unzipped");
        std::fs::create_dir_all(exe_dir.join("sub")).unwrap();
        std::fs::create_dir_all(&src).unwrap();

        // "running" app files
        std::fs::write(exe_dir.join(APP_EXE_NAME), b"old-exe").unwrap();
        std::fs::write(exe_dir.join(WINTUN_NAME), b"old-dll").unwrap();

        // "new" build inside a nested folder, as Expand-Archive may produce
        std::fs::create_dir_all(src.join("rvpn-windows-v9.9.9-win64")).unwrap();
        std::fs::write(src.join("rvpn-windows-v9.9.9-win64").join(APP_EXE_NAME), b"new-exe").unwrap();
        std::fs::write(src.join("rvpn-windows-v9.9.9-win64").join(WINTUN_NAME), b"new-dll").unwrap();

        let new_exe = install_from(&src, &exe_dir).unwrap();
        assert_eq!(new_exe, exe_dir.join(APP_EXE_NAME));
        assert_eq!(std::fs::read(&new_exe).unwrap(), b"new-exe");
        assert_eq!(std::fs::read(exe_dir.join(WINTUN_NAME)).unwrap(), b"new-dll");
        assert_eq!(std::fs::read(exe_dir.join(format!("{APP_EXE_NAME}.old"))).unwrap(), b"old-exe");
        assert_eq!(std::fs::read(exe_dir.join(format!("{WINTUN_NAME}.old"))).unwrap(), b"old-dll");
    }

    #[test]
    #[ignore = "network + live GitHub release"]
    fn fetch_latest_finds_a_zip() {
        let info = fetch_latest().unwrap();
        assert!(info.tag.starts_with('v'), "tag={}", info.tag);
        assert!(info.url.contains("win64.zip"), "url={}", info.url);
        println!("latest: {} → {}", info.tag, info.url);
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;

    /// Full real cycle against the live GitHub release: fetch → download →
    /// extract → install into a scratch folder (with fake "running" files).
    #[test]
    #[ignore = "network + live GitHub release (downloads the real zip)"]
    fn download_and_install_real_release() {
        let info = fetch_latest().expect("fetch latest");
        let dir = tempfile::tempdir().unwrap();
        let exe_dir = dir.path().join("app");
        std::fs::create_dir_all(&exe_dir).unwrap();
        std::fs::write(exe_dir.join(APP_EXE_NAME), b"old-exe").unwrap();

        let new_exe = download_and_install(&info.url, &exe_dir).expect("install");
        assert!(new_exe.is_file());
        let meta = std::fs::metadata(&new_exe).unwrap();
        assert!(meta.len() > 1_000_000, "suspiciously small exe: {}", meta.len());
        assert!(std::fs::read(exe_dir.join(format!("{APP_EXE_NAME}.old"))).unwrap() == b"old-exe");
        assert!(exe_dir.join(WINTUN_NAME).is_file(), "wintun.dll not installed");
        println!("cycle OK: {} ({} bytes) from {}", new_exe.display(), meta.len(), info.tag);
    }
}
