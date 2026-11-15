# R-VPN Windows Client — Source

Windows client for [rVPN](https://rvpn.org/) — built on the same production
engine as the official macOS/iOS/Android apps (`rvpn-mobile`), driven
in-process with no FFI boundary.

This repository contains TWO projects that must stay side by side
(the app's Cargo.toml references the engine via a relative path):

```
├── rVPN-core/      rVPN engine (local fork with the Windows patches — windows-client branch)
└── rvpn-windows/   the Windows app (GUI + TUN + proxy + v2rayN-style routing)
```

## Build

Requirements: Rust (MSVC toolchain) + Visual Studio Build Tools (C++
workload) + [`wintun.dll`](https://www.wintun.net/builds/wintun-0.14.1.zip)
(SHA-256 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`).

```bash
cd rvpn-windows
cargo build --release
cp target/release/rvpn-windows.exe <output dir>/
cp assets/wintun.dll              <output dir>/   # or download from the link above
```

`rvpn-windows.exe` and `wintun.dll` must sit next to each other. Running
requires Administrator (TUN adapter creation).

## Key docs

- `rvpn-windows/README.md` — architecture, build, usage (EN/FA)
- `rvpn-windows/PATCHES.md` + `rvpn-windows/patches/` — engine changes vs
  upstream, including three real bug fixes found in the field (WS parser
  stuck frames, flow framing, duplicated SOCKS4 reply)
- `rvpn-windows/ROUTING.md` — Direct/Proxy/Block routing system
- `rvpn-windows/assets/GEODATA.md` — GeoIP/GeoSite databases + auto-update

## License

AGPL-3.0-or-later (same as rVPN-core). Wintun is Apache-2.0.
