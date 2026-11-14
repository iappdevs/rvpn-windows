# rvpn-windows — R-VPN Client for Windows

**English** | [فارسی](#فارسی)

A native Windows client for [rVPN](https://rvpn.org/) — the open-source,
censorship-resistant VPN that disguises traffic as ordinary HTTPS
(WebSocket over TLS 1.3, X3DH + Double Ratchet end-to-end encryption).

This is the missing Windows sibling of the official macOS/iOS/Android apps,
built on the **same production engine** (`rvpn-mobile`'s `IosTunClient`) —
used in-process, with no FFI boundary.

## Features

- **Full-tunnel TUN mode** via Wintun — all IPv4 traffic routed through the
  tunnel (`0.0.0.0/1` + `128.0.0.0/1` half-default routes)
- **IPv6 leak guard** — v6 default routes pinned to the tunnel; packets are
  encrypted and dropped server-side, never leaked in the clear
- **DNS leak protection** — loopback DoH proxy (same `DnsServer` as the
  macOS app) + NRPT `.` rule covering v4/v6/multi-homed lookups
- **Ad & tracker blocking** at the DNS layer (always on, like macOS)
- **Split tunnel** — bypass CIDRs and builtin country lists (e.g. bypass
  `IR`/`CN` ranges) routed via the original gateway
- **TOFU server identity pinning** (`ik:1:<base32>`) with first-connect
  capture and a mismatch alert dialog — same trust model as the macOS app
- **Profiles** (up to 10) with identity keygen/import, prekey bundle import,
  and `.rvpn` export/import (with or without the private key)
- **Tray-first UX** — state-coloured tray icon, connect/disconnect from the
  menu, window parks to tray on close
- **Auto-reconnect** with PSK TLS resumption (1-RTT), re-addressing when the
  server assigns a new virtual IP
- Single instance, launch-at-startup, live log view, capped log files

## Distribution layout

```
rvpn-windows.exe   the client (requires Administrator — UAC prompt on launch)
wintun.dll         the official Wintun 0.14.1 driver binding (amd64)
```

Both files must sit in the same folder.

## Building

Prerequisites: Rust (MSVC toolchain) + Visual Studio Build Tools (C++ workload).

```bash
# 1. rVPN-core (upstream engine) — sibling checkout, windows-client branch
git clone https://github.com/PDG-Global/rVPN-core.git ../rVPN-core
cd ../rVPN-core && git checkout windows-client   # or apply PATCHES.md

# 2. build
cargo build --release

# 3. assemble
cp target/release/rvpn-windows.exe dist/
cp assets/wintun.dll dist/
```

`wintun.dll` is the official build from
[wintun.net](https://www.wintun.com/builds/wintun-0.14.1.zip)
(SHA-256 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`)
— verify the hash before shipping; it is a kernel driver.

## Usage

1. Run `rvpn-windows.exe` (accept the UAC prompt — the TUN adapter needs it).
2. **Profiles → + New**: set a name and your server address
   (e.g. `wss://your-server.com:443/api/v1/ws/tun`).
3. Click **Generate** for the identity key, **Import…** for the server's
   `prekey-bundle.json`.
4. Back on **Connect**, hit **Connect**. The first successful connection
   captures and stores the server's identity pin (TOFU).

Diagnostics: set `RVPN_LOG_LEVEL=debug` (or `trace`) before launching; logs
land in `%LOCALAPPDATA%\rvpn-windows\logs\`.

## Architecture

```
┌─────────────────────────── rvpn-windows.exe ───────────────────────────┐
│ GUI (egui) + tray        engine threads          OS plumbing           │
│ ┌──────────┐  events  ┌──────────────────────┐  ┌────────────────────┐ │
│ │ app.rs   │◄────────►│ engine.rs            │─►│ tundevice.rs       │ │
│ │ tray.rs  │  poll    │  IosTunClient        │  │  (wintun.dll)      │ │
│ └──────────┘          │  (rvpn-mobile)       │  ├────────────────────┤ │
│                       │  DoH DNS proxy :53   │─►│ winroute.rs        │ │
│                       │  pump threads ×2     │  │  (netsh/NRPT/PS)   │ │
│                       └──────────────────────┘  └────────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

- `engine.rs` — lifecycle (connect/teardown), the Wintun ⇄ engine packet
  pumps, TOFU events, re-address handling. Failure-safe: resources unwind
  in reverse order via `Drop`.
- `tundevice.rs` — Wintun adapter (create/address/DNS/MTU natively, ring
  session for packets).
- `winroute.rs` — half-default routes, IPv6 guard, split-tunnel bypasses,
  NRPT rule; captured original gateway; everything reversible.
- `profile.rs` / `identity.rs` — profile store, `.rvpn` import/export,
  identity keygen, pin computation.
- TLS backend: **rustls** (the same stack iOS ships in production). The
  macOS client uses BoringSSL for Chrome ClientHello mimicry; on Windows
  that would require cmake+nasm for no protocol benefit — see PATCHES.md.

## Security notes

- End-to-end encryption happens in `rvpn-core` (audited upstream); the
  relay server only ever sees ciphertext.
- TOFU pins are enforced at engine construction; a mismatch never connects.
- Known limitation (shared with every userspace VPN without WFP filters):
  apps with hardcoded DoH (some browsers) bypass the system resolver.
  The v6 half-routes and NRPT rule close the common paths; full DoH
  blocking would need Windows Filtering Platform rules (future work).

## License

AGPL-3.0-or-later (same as rVPN-core). Wintun is Apache-2.0.

---

# فارسی

**کلاینت ویندوزی rVPN** — هم‌خانواده‌ی اپ‌های رسمی مک/آیفون/اندروید، با
**همان موتور پروداکشن** (`rvpn-mobile`) که درون پروسه و بدون مرز FFI اجرا
می‌شود.

## قابلیت‌ها

- **تونل کامل** با Wintun — کل ترافیک IPv4 از تونل رد می‌شود
- **جلوگیری از نشت IPv6 و DNS** — پروکسی DoH روی 127.0.0.1 + قانون NRPT
- **مسدودسازی تبلیغات** در لایه‌ی DNS (همیشه روشن، مثل اپ مک)
- **اسپلیت‌تونل** — عبور مستقیم رنج‌های ایران/چین/… از گیت‌وی اصلی
- **پین‌کردن هویت سرور (TOFU)** با هشدار در صورت تغییر کلید
- **پروفایل‌ها** (تا ۱۰ عدد)، ساخت/درون‌ریزی هویت و prekey bundle،
  خروجی/ورودی فایل `.rvpn`
- **آیکون tray** با رنگ وضعیت، اتصال/قطع از منوی tray
- اتصال مجدد خودکار، اجرا در استارت‌آپ، نمایش لاگ زنده

## اجرا

1. `rvpn-windows.exe` را اجرا کنید (نیاز به تأیید UAC دارد — ساخت
   آداپتر TUN به مجوز ادمین نیاز دارد).
2. در **Profiles** یک پروفایل بسازید، آدرس سرور را وارد کنید
   (`wss://server:443/api/v1/ws/tun`).
3. **Generate** برای کلید هویت و **Import…** برای
   `prekey-bundle.json` سرور.
4. در صفحه‌ی **Connect** دکمه‌ی اتصال را بزنید. بار اول، پین هویت سرور
   ذخیره می‌شود (TOFU).

فایل `wintun.dll` باید کنار exe باشد.

## ساخت

```bash
cargo build --release
cp target/release/rvpn-windows.exe assets/wintun.dll dist/
```

ریپوی `rVPN-core` (شاخه‌ی `windows-client`) باید به‌صورت پوشه‌ی هم‌جوار
`../rVPN-core` موجود باشد — یا تغییرات `PATCHES.md` را روی upstream
اعمال کنید.

برای لاگ تفصیلی: `RVPN_LOG_LEVEL=debug` — لاگ‌ها در
`%LOCALAPPDATA%\rvpn-windows\logs\`.
