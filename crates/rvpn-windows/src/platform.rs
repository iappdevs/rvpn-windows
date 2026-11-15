//! Windows platform helpers: elevation check, single-instance mutex,
//! and the startup registry entry.

use std::io;
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, HANDLE};
use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows_sys::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, OpenProcessToken,
};

/// Is the process running elevated (Administrator)?
pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        windows_sys::Win32::Foundation::CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// Guard for the single-instance named mutex. If another instance holds it,
/// `try_acquire` returns `None`.
pub struct SingleInstance {
    handle: HANDLE,
}

impl SingleInstance {
    pub fn try_acquire() -> Option<Self> {
        Self::acquire_named("Global\\rvpn-windows-singleton")
    }

    fn acquire_named(name: &str) -> Option<Self> {
        let name: Vec<u16> = format!("{name}\0").encode_utf16().collect();
        unsafe {
            let handle = CreateMutexW(std::ptr::null(), 0, name.as_ptr());
            // CreateMutexW returns a valid handle even on ERROR_ALREADY_EXISTS;
            // that error is what tells us another instance is running.
            if handle.is_null() {
                return None;
            }
            if io::Error::last_os_error().raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32) {
                windows_sys::Win32::Foundation::CloseHandle(handle);
                return None;
            }
            Some(Self { handle })
        }
    }
}

impl Drop for SingleInstance {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

/// Bring the already-running instance's window to the foreground.
pub fn activate_running_instance() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        FindWindowW, SetForegroundWindow, SW_RESTORE, ShowWindow,
    };

    // The egui viewport is titled "R-VPN" (updated with state as
    // "R-VPN — Connected" etc.), so match by the "R-VPN" prefix.
    let title: Vec<u16> = "R-VPN\0".encode_utf16().collect();
    unsafe {
        let hwnd = FindWindowW(std::ptr::null(), title.as_ptr());
        if !hwnd.is_null() {
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
        }
    }
}

const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const RUN_VALUE: &str = "rvpn-windows";

/// Register/unregister this executable in the current user's startup entries.
pub fn set_launch_at_startup(enabled: bool) -> anyhow::Result<()> {
    use winreg::enums::KEY_SET_VALUE;

    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    let key = hkcu.open_subkey_with_flags(RUN_KEY, KEY_SET_VALUE)?;
    if enabled {
        let exe = std::env::current_exe()?;
        key.set_value(RUN_VALUE, &format!("\"{}\"", exe.display()))?;
    } else {
        let _ = key.delete_value(RUN_VALUE);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elevation_check_does_not_crash() {
        let _ = is_elevated();
    }

    #[test]
    fn single_instance_mutex_roundtrip() {
        // A private mutex name: the real app instance (often running while
        // tests execute) legitimately holds the production name.
        let test_name = format!(
            "Global\\rvpn-windows-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let first = SingleInstance::acquire_named(&test_name);
        assert!(first.is_some());
        let second = SingleInstance::acquire_named(&test_name);
        assert!(second.is_none());
        drop(first);
        let third = SingleInstance::acquire_named(&test_name);
        assert!(third.is_some());
    }
}

// ============================================================================
// Main-window visibility (Win32, independent of the egui repaint loop)
//
// Hiding the egui viewport via ViewportCommand::Visible(false) lets the
// winit loop stall once hidden — the matching Visible(true) from a tray
// click is then never processed and the window stays gone forever. These
// helpers drive the real HWND instead, which works regardless of repaints.
// ============================================================================

use std::sync::atomic::{AtomicIsize, Ordering as AtomicOrdering};

static MAIN_HWND: AtomicIsize = AtomicIsize::new(0);

extern "system" fn enum_windows_proc(
    hwnd: windows_sys::Win32::Foundation::HWND,
    _lparam: windows_sys::Win32::Foundation::LPARAM,
) -> windows_sys::Win32::Foundation::BOOL {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId,
    };
    unsafe {
        let mut pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, &mut pid);
        if pid != std::process::id() {
            return 1; // not ours — keep enumerating
        }
        let len = GetWindowTextLengthW(hwnd);
        if len <= 0 {
            return 1; // untitled helper window (tray, message-only)
        }
        let mut buf = vec![0u16; (len + 1) as usize];
        let n = GetWindowTextW(hwnd, buf.as_mut_ptr(), len + 1);
        let title = String::from_utf16_lossy(&buf[..n.max(0) as usize]);
        // All our viewport titles start with "R-VPN" ("R-VPN — Connected", …).
        if title.starts_with("R-VPN") {
            MAIN_HWND.store(hwnd as isize, AtomicOrdering::SeqCst);
            return 0; // found — stop
        }
        1
    }
}

/// Find (once) the HWND of the main window of THIS process.
fn main_window_handle() -> windows_sys::Win32::Foundation::HWND {
    let cached = MAIN_HWND.load(AtomicOrdering::SeqCst);
    if cached != 0 {
        return cached as windows_sys::Win32::Foundation::HWND;
    }
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::EnumWindows(
            Some(enum_windows_proc),
            0,
        );
    }
    MAIN_HWND.load(AtomicOrdering::SeqCst) as windows_sys::Win32::Foundation::HWND
}

/// Bring the main window up from the tray (no-op if already visible).
pub fn show_main_window() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        IsIconic, IsWindowVisible, SetForegroundWindow, ShowWindow, SW_RESTORE, SW_SHOW,
    };
    let hwnd = main_window_handle();
    if hwnd.is_null() {
        return;
    }
    unsafe {
        if IsWindowVisible(hwnd) == 0 {
            ShowWindow(hwnd, if IsIconic(hwnd) != 0 { SW_RESTORE } else { SW_SHOW });
        }
        let _ = SetForegroundWindow(hwnd);
    }
}

/// Park the main window in the tray (no-op if already hidden).
pub fn hide_main_window() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{IsWindowVisible, ShowWindow, SW_HIDE};
    let hwnd = main_window_handle();
    if hwnd.is_null() {
        return;
    }
    unsafe {
        if IsWindowVisible(hwnd) != 0 {
            ShowWindow(hwnd, SW_HIDE);
        }
    }
}
