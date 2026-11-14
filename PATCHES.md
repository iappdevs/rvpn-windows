# Patches to rVPN-core (upstream)

The Windows client depends on a small, surgical patch set against
[`PDG-Global/rVPN-core`](https://github.com/PDG-Global/rVPN-core). It is
committed on the `windows-client` branch of the sibling `../rVPN-core`
checkout, and mirrored in `patches/` here.

Two commits:

1. `windows-direct-tun` feature on `rvpn-mobile` (porting + gating; see below).
2. **A genuine upstream bug fix** — `MinimalWsReader::next_frame` parsed a
   frame only after a *successful* read. When one TCP segment delivered
   several WebSocket frames (e.g. a data batch right behind the server's
   keepalive ping), the frames after the first were stuck: the parser waited
   for a new segment — forever, or until misreporting EOF at close. This
   stalls the mobile downlink in the field; the fix parses the buffer
   before reading, and is covered by a new unit test
   (`ws::frame_stream_tests::next_frame_parses_back_to_back_frames_in_one_segment`).

## Extra-root TLS deployments

`rvpn-tls` (rustls backend) accepts `RVPN_TLS_ROOT_CA=/path/to.pem` to
append extra trust roots — for servers terminating TLS with a private CA or
a direct-IP certificate (no public CA issues certificates for bare IPs, so
a domain + Let's Encrypt remains the recommended production setup).

## Summary of changes

### 1. `rvpn/crates/rvpn-mobile/Cargo.toml`

- New feature **`windows-direct-tun`** — mirrors the iOS feature set
  (rustls TLS backend, `dns`) so the direct-TUN engine modules compile on
  Windows:
  ```toml
  windows-direct-tun = ["dns", "rustls", "tokio-rustls", "rustls-platform-verifier",
                        "webpki-roots", "tokio-tungstenite/__rustls-tls", "rvpn-tls/rustls"]
  ```
- `[target.'cfg(target_os = "windows")'.dependencies]` re-enables
  `rvpn-split-tunnel` with builtin data (bypass-country CIDR lists), the
  same as the existing macOS/Android target blocks.

### 2. `rvpn/crates/rvpn-mobile/src/lib.rs`

- The host-agnostic direct-TUN modules (`ios_tun`, `ios_tun_ffi`,
  `server_session`) now also compile under `windows-direct-tun`.
  `swift_crypto` remains iOS/macOS-only.

### 3. `rvpn/crates/rvpn-mobile/src/server_session.rs`

- TLS type aliases and the connect call select **rustls** when
  `ios-direct-tun` **or** `windows-direct-tun` (previously iOS-only); the
  boring (Chrome-mimicry) branch applies otherwise, unchanged.

### 4. `rvpn/crates/rvpn-mobile/src/flow_connector.rs` and `doh_client.rs`

- Same rustls/boring feature split extended to `windows-direct-tun`;
  `FlowConnectorConfig::resumption` field gating extended (was
  iOS/macOS-only).

### 5. `rvpn/crates/rvpn-mobile/src/ios_tun.rs`

- Apple-only code — the libmalloc `extern "C"` zone APIs,
  `all_zone_ptrs`, `all_zones_pressure_relief` — is now gated behind
  `target_vendor = "apple"` with a no-op `all_zones_pressure_relief` stub
  for other vendors (it is called unconditionally by the keepalive).
  Behaviour on Apple platforms is unchanged.

### 6. `rvpn/crates/rvpn-mobile/src/ios_tun_ffi.rs`

- `start_dns_proxy_for_direct_tun` is now `pub` so host apps can start the
  loopback DoH DNS proxy natively in-process (the Windows client does).
- The non-diagnostics `rvpn_tun_get_rss_bytes` Mach reader is now Apple-only
  (no Mach on Windows).

### 7. `rvpn/crates/rvpn-mobile/src/ws.rs` (upstream bug fix)

- `MinimalWsReader::next_frame` extracted a `try_parse_frame` helper and
  parses buffered frames **before** waiting on the stream (commit 2 above).

### 8. `rvpn/crates/rvpn-tls` (rustls backend)

- Optional `RVPN_TLS_ROOT_CA` extra roots via `rustls-pemfile` (see above).

## Why rustls instead of BoringSSL on Windows?

The macOS client uses the boring backend to mimic Chrome's ClientHello
shape. Building BoringSSL on Windows MSVC requires cmake + nasm in the
toolchain. The iOS production builds already ship rustls — TLS 1.3 is all
the protocol requires — so Windows follows iOS. Switching later only
involves flipping the feature wiring above (plus a cmake/nasm CI step).
