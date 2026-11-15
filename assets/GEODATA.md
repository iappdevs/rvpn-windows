# Bundled routing data

`geoip.dat` and `geosite.dat` are embedded in the executable; recipients do
not need separate data files. They use V2Ray's protobuf format. The embedded
snapshot below is the offline fallback. Before each Proxy connection, the
app checks the latest stable release from the same repository through the
internal rVPN SOCKS tunnel, before setting Windows system proxy.

The app uses a conditional GitHub release request (ETag), compares release
and asset metadata, and downloads a changed pair from one immutable tagged
release. Both SHA-256 checksum files, optional GitHub asset digests, bounded
file sizes, protobuf structures and required groups must validate before
an atomic pointer publishes the pair. Downloads have timeouts. Failed or
partial downloads retain the previous verified pair; if there is no valid
cache, the embedded snapshot is used. Connect displays the active version
and update status; an unavailable check does not claim that data is current.

Verified generations persist under `%LOCALAPPDATA%\rvpn-windows\geodata\`.
Country and GeoSite selectors refresh after an update; the router for that
connection uses the new pair immediately. Starting the app uses saved data
without a network request. Updates affect proxy routing, not TUN's existing
split-tunnel implementation.

- Source: https://github.com/Loyalsoldier/v2ray-rules-dat
- Release: https://github.com/Loyalsoldier/v2ray-rules-dat/releases/tag/202611132203
- Retrieved: 2026-11-14
- `geoip.dat` SHA-256: `304ac8a1cbcc8166e4f5a4f32955e4d0fb77a1bd713583e371b30ee27f3659d8`
- `geosite.dat` SHA-256: `6206c215d45f1acb663336b17a77ad5be62709680dc1ac2b2194121d6a1680f5`
- Both hashes matched the release's `.sha256sum` assets.
- Upstream license: [geodata-LICENSE.txt](geodata-LICENSE.txt) (GPL-3.0).
  See upstream README for the underlying datasets and attribution.
- Wire schema: https://github.com/v2fly/v2ray-core/blob/master/app/router/routercommon/common.proto

To refresh the embedded fallback for a new build, download both files and their matching checksum files from a
single tagged release, verify SHA-256, replace these assets, update this
record, and run the routing tests before rebuilding the executable.
