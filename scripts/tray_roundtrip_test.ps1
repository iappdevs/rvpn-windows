# Tray round-trip test: close window to tray, verify hidden, then show it
# the same way the app's tray handler now does (direct Win32 ShowWindow).
$ErrorActionPreference = 'Stop'
Start-Transcript -Path "$env:TEMP\tray-test-output.txt" -Force | Out-Null
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class W32 {
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr FindWindowW(string cls, string title);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
}
'@

function Find-Main {
    $p = Get-Process rvpn-windows -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 }
    if ($p) { return [IntPtr]$p[0].MainWindowHandle }
    foreach ($t in @('R-VPN', 'R-VPN - Connected', 'R-VPN — Connected')) {
        $h = [W32]::FindWindowW($null, $t)
        if ($h -ne [IntPtr]::Zero) { return $h }
    }
    return [IntPtr]::Zero
}

$h = Find-Main
if ($h -eq [IntPtr]::Zero) { Write-Host 'FAIL: window not found''; Stop-Transcript | Out-Null; exit 1 }
$vis0 = [W32]::IsWindowVisible($h)
Write-Host "step1 found window, visible=$vis0"

# Close it (same as clicking X) -> should park in tray
[W32]::PostMessage($h, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
Start-Sleep -Seconds 2
$vis1 = [W32]::IsWindowVisible($h)
Write-Host "step2 after close-to-tray, visible=$vis1 (expect False)"
if ($vis1) { Write-Host 'FAIL: window did not hide''; Stop-Transcript | Out-Null; exit 1 }

# Alive?
$p = Get-Process rvpn-windows -ErrorAction SilentlyContinue
if (-not $p) { Write-Host 'FAIL: process died''; Stop-Transcript | Out-Null; exit 1 }
Write-Host "step3 process alive (pid $($p[0].Id))"

# Show it the way the tray handler does now
[W32]::ShowWindow($h, 9) # SW_RESTORE
[W32]::SetForegroundWindow($h) | Out-Null
Start-Sleep -Seconds 2
$vis2 = [W32]::IsWindowVisible($h)
Write-Host "step4 after win32 show, visible=$vis2 (expect True)"
if (-not $vis2) { Write-Host 'FAIL: window did not come back''; Stop-Transcript | Out-Null; exit 1 }

Write-Host 'TRAY ROUND-TRIP PASS'
Stop-Transcript | Out-Null
exit 0
