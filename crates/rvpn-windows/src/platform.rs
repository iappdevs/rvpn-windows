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
        let name: Vec<u16> = "Global\\rvpn-windows-singleton\0".encode_utf16().collect();
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
        let first = SingleInstance::try_acquire();
        assert!(first.is_some());
        let second = SingleInstance::try_acquire();
        assert!(second.is_none());
        drop(first);
        let third = SingleInstance::try_acquire();
        assert!(third.is_some());
    }
}
