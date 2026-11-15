# R-VPN for Windows

[![platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue)](https://github.com/iappdevs/rvpn-windows)
[![engine](https://img.shields.io/badge/engine-rvpn--mobile-orange)](https://github.com/PDG-Global/rVPN-core)
[![license](https://img.shields.io/badge/license-AGPL--3.0--or--later-green)](LICENSE)

**The Windows client for [rVPN](https://rvpn.org/)** — the open-source,
censorship-resistant VPN protocol from [`PDG-Global/rVPN-core`](https://github.com/PDG-Global/rVPN-core).

rVPN disguises your traffic as ordinary HTTPS (WebSocket over TLS 1.3) with
end-to-end X3DH + Double Ratchet encryption — the relay server only ever sees
ciphertext. This app brings it to Windows with the same production engine
the official macOS / iOS / Android clients ship (`rvpn-mobile`), running
in-process with no FFI boundary.

> Unofficial community client. Upstream project: **[PDG-Global/rVPN-core](https://github.com/PDG-Global/rVPN-core)** · docs: [docs.rvpn.org](https://docs.rvpn.org)

---

## Features

- **Two connection modes**, switchable right on the Connect page
  - **Full tunnel (TUN)** — every packet of the system routed through the
    encrypted tunnel (Wintun), IPv6 leak-guarded, no Administrator juggling
    beyond the UAC prompt
  - **SOCKS5 + HTTP proxy** — a local proxy on `127.0.0.1:<port>` that sets
    the Windows system proxy for you (and restores your previous settings on
    disconnect); works without Administrator
- **v2rayN-style routing** — per-rule **Direct / Proxy / Block** for domains,
  IPs and countries, ordered rules, default route, one-click *Iran direct*
  preset
- **GeoIP + GeoSite built in** — 250 countries / 1.5k domain groups
  (Loyalsoldier data) embedded, and auto-updated through the tunnel before
  the system proxy is touched
- **Routing DNS through the tunnel** — locally poisoned answers can no
  longer push sites to the wrong route
- **TOFU server-identity pinning** (`ik:1:…`) — first connect captures the
  server's identity; any key change triggers an explicit trust dialog
- **Ad & tracker blocking** at the DNS layer
- **Live session stats** — cumulative upload/download, uptime, virtual IP
- **Profile system** — up to 10 profiles, identity keygen/import,
  `.rvpn` export/import (with or without the private key)
- **Tray-first UX** — state-coloured tray icon, connect/disconnect from the
  menu; closing to tray (opt-in) and raising the window both verified
  rock-solid
- Crash-safe teardown: NRPT rules, system proxy and routes are always
  restored — even after a forced kill (helper + startup self-healing)

## Getting started

1. Get [`wintun.dll`](https://www.wintun.net/builds/wintun-0.14.1.zip)
   (SHA-256 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`)
   and put it next to `rvpn-windows.exe`.
2. Run `rvpn-windows.exe` **as Administrator** (TUN mode needs it; proxy
   mode doesn't).
3. Create a profile: server address (e.g. `wss://your-server.com:443/api/v1/ws/tun`),
   **Generate** an identity key, import the server's `prekey-bundle.json`.
4. Pick a mode and press **Connect**. First connect pins the server
   identity (TOFU).

For browser-only tunneling, switch the profile to **SOCKS5 proxy** mode —
the system proxy is wired for you (Chrome/Edge follow it automatically).

## Repository layout

```
├── README.md            ← you are here
├── rVPN-core/           ← rVPN engine (fork of PDG-Global/rVPN-core, windows-client branch)
│   └── rvpn/crates/
│       ├── rvpn-core/       protocol + crypto (X3DH, Double Ratchet)
│       ├── rvpn-tls/        TLS backends (rustls / boring)
│       ├── rvpn-mobile/     the app-grade engine used in-process here
│       └── …
└── rvpn-windows/        ← the Windows app
    ├── crates/rvpn-windows/src/
    │   ├── engine.rs    TUN + proxy lifecycles, pumps, teardown
    │   ├── routing.rs   Direct/Proxy/Block rule engine
    │   ├── proxy.rs     shared HTTP+SOCKS front
    │   ├── tundevice.rs Wintun adapter
    │   ├── sysproxy.rs  WinINET system proxy with backup/restore
    │   ├── geodata.rs   GeoIP/GeoSite loading + auto-update
    │   └── ui.rs        the interface
    ├── patches/         engine changes vs upstream (bug fixes — PR-ready)
    └── assets/          geo databases, sample profile
```

The two folders must stay side by side — the app's `Cargo.toml` references
the engine with a relative path.

## Building from source

Requirements: **Rust (MSVC)** + **Visual Studio Build Tools** (C++ workload).

```bash
cargo build --release          # from rvpn-windows/
cp target/release/rvpn-windows.exe  <outdir>/
cp assets/wintun.dll               <outdir>/   # or download (link above)
```

Run the test suite:

```bash
cargo test --no-default-features          # 39 unit tests
RVPN_TEST_SERVER=wss://host:443/api/v1/ws/tun \
  cargo test --release --no-default-features --test e2e_proxy -- --ignored --test-threads=1
```

## Relationship with upstream

`rVPN-core/` is a fork of [`PDG-Global/rVPN-core`](https://github.com/PDG-Global/rVPN-core)
carrying a small, surgical patch set (see
[`rvpn-windows/PATCHES.md`](rvpn-windows/PATCHES.md) and `rvpn-windows/patches/`):

1. `windows-direct-tun` feature — compiles the engine on Windows (rustls
   backend, same stack as the iOS production builds)
2. **WS parser fix** — frames buffered behind the first frame of a TCP
   segment were stuck forever (downlink stall; affects the official mobile
   apps too — PR-ready)
3. **Flow-connector fixes** — broken first-message framing (JSON instead of
   binary, missing padding) that made SOCKS flows fail immediately
4. **SOCKS4/4a support** — the dialect Windows' own system proxy speaks,
   including a duplicated-reply fix that corrupted every proxied page load

All wire-protocol behaviour of existing platforms is unchanged.

## Security notes

- End-to-end encryption in `rvpn-core`; the relay only forwards ciphertext
- TOFU pins enforced before any connection attempt
- The prekey bundle and `.rvpn` profiles contain **public** key material
  only — the identity key never leaves the machine unless you explicitly
  export it inside the profile

## License

AGPL-3.0-or-later, same as upstream rVPN-core. Wintun is Apache-2.0.

Credits: [PDG Global](https://github.com/PDG-Global) for rVPN,
[Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat)
for the geo databases, [Wintun](https://www.wintun.net) for the TUN driver.
