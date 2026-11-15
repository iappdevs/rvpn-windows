# System proxy routing

The implementation follows v2rayN's division of responsibility: Windows
points at a local HTTP proxy; the local routing engine selects Direct or
Proxy. Windows ProxyOverride is not a country/CIDR routing engine.

References reviewed at v2rayN commit
`2c90ed1a9438a499aaaea0b612ffd5d705970106`:

- [Windows proxy setup](https://github.com/2dust/v2rayN/blob/2c90ed1a9438a499aaaea0b612ffd5d705970106/v2rayN/ServiceLib/Handler/SysProxy/SysProxyHandler.cs)
- [Ordered routing rules](https://github.com/2dust/v2rayN/blob/2c90ed1a9438a499aaaea0b612ffd5d705970106/v2rayN/ServiceLib/Services/CoreConfig/V2ray/V2rayRoutingService.cs)
- [V2Ray routing semantics](https://www.v2fly.org/en_US/config/routing.html)

This is a Rust implementation for rVPN, not an embedded Xray/V2Ray core.
rVPN's encrypted wire protocol and server remain unchanged. It supports
the destination-based subset below, not V2Ray config files, process/port
rules, balancers, or the `ext:` syntax. Regex rules use Rust regex syntax
(no lookaround/backreferences).

## Use

1. Select the profile, choose Proxy mode, then open **Routing**.
2. Choose **More → Preset: Iran direct** for `.ir` domains, Iranian IPs (IPv4 and
   IPv6) and private networks direct, with other destinations proxied.
3. Use **Add Rule** or double-click a table row. The details dialog uses
   v2rayN's Windows form order and three Domain / IP / Process columns.
   Choose `direct`, `proxy` or `block` in **outboundTag**; use **Add GeoSite**
   and **Add country / GeoIP** to insert bundled groups. Confirm the dialog.
4. Use Up/Down/Top/Bottom or the row context menu to set priority. Choose
   the default outbound, then **Confirm** the main panel and reconnect.
   Dialog confirmation stages the edit; main-panel confirmation saves it.
   Main-panel Cancel restores the last saved rules and ad-block preference.

## Windows v2rayN layout reference

The routing panel follows the Windows WPF layouts from the same pinned
v2rayN commit cited above:

- [RoutingRuleSettingWindow.xaml](https://github.com/2dust/v2rayN/blob/2c90ed1a9438a499aaaea0b612ffd5d705970106/v2rayN/v2rayN/Views/RoutingRuleSettingWindow.xaml)
- [RoutingRuleDetailsWindow.xaml](https://github.com/2dust/v2rayN/blob/2c90ed1a9438a499aaaea0b612ffd5d705970106/v2rayN/v2rayN/Views/RoutingRuleDetailsWindow.xaml)

The toolbar, ordered Rule List and Confirm/Cancel workflow follow those layouts.
The redesigned workspace shows four useful columns: enabled, rule name,
outboundTag and Domain / IP, with responsive widths. Unused subscription/icon
fields are omitted from the main settings form. The details dialog
keeps the remarks/type/outbound/port/protocol/inbound/network form and three
equal editor columns. Rendering uses egui controls, not native WPF controls.
Xray/sing-box/process/port/protocol and subscription fields that RVPN cannot
execute are visibly disabled. JSON import/export uses RVPN routing JSON;
it does not claim compatibility with v2rayN configuration files.

The route tester is under **More → Test routing decision**. Row selection
supports Ctrl/Shift clicks, selection export and stable multi-row movement.
Headless egui tests verify editor cancellation, ordering and visible footer /
column placement. To reproduce the software-rendered UI previews:

```powershell
$env:RVPN_UI_PREVIEW_DIR = 'D:\preview'
cargo test --release --no-default-features --lib routing_ui::tests
python scripts/render_egui_preview.py D:\preview\routing-panel.json D:\preview\routing-rule-details.json
```

A country refers to the **destination IP's country**, not the exit server's
location or a site's nationality. A domestic site behind a foreign CDN
needs a domain Direct rule, for example `domain:digikala.com`. To force a
site through Proxy even if its IP is Iranian, add a Proxy domain rule.

Supported entries:

| Entry | Meaning |
| --- | --- |
| `domain:example.com` | Domain and all subdomains |
| `full:example.com` | Exact domain |
| `*.example.com` | Subdomains only |
| `example` | Keyword/substring, as in V2Ray |
| `regexp:^bank[0-9]+\.ir$` | Regex against the normalized domain |
| `geosite:google` | Bundled domain group; `@attribute` filters supported |
| `5.160.0.1`, `5.160.0.0/16`, `2001:db8::/32` | IP/CIDR |
| `geoip:ir`, `geoip:private`, `geoip:!ir` | Bundled country/group or its inverse |

Domains and IPs within a row are alternatives, matching v2rayN's generation
of separate domain and IP field rules. Rules of each stage are evaluated
top to bottom; first match wins. When enabled, ad/tracker blocking precedes
the user rules and can be disabled on the Routing page.

- **IPIfNonMatch** (default): try domain rules, then resolve and try IP rules.
- **IPOnDemand**: resolve when an IP rule is reached; earlier IP rules can
  override later domain rules.
- **AsIs**: do not resolve hostnames for routing; literal IPs still match.

In production proxy mode, DNS for country/IP classification uses the
profile's tunnel resolvers over DNS-over-TCP through the encrypted rVPN
backend. It never falls back to Windows or the bypass DNS. This prevents
filtered names resolving to a censorship address such as `10.10.34.36`
and accidentally matching `geoip:private` as Direct. A small reusable
connection pool and per-host cache coalesce concurrent browser lookups.
Explicit Direct domain rules use the profile's bypass resolvers, keeping
domestic DNS independent of the tunnel. All DNS operations have timeouts.
For IP-based Direct matches, the
matched addresses are reused for dialing, avoiding a second lookup that
could change the result. A routing DNS failure returns a proxy error;
it does not silently change the selected policy. Proxy destinations retain
their original domain for the rVPN server.

### Diagnosing a running backend without changing system settings

`examples/proxy_probe.rs` starts an ephemeral test frontend against an
already-running internal SOCKS backend. It does not read stored identities
or profiles, set Windows proxy, or stop the active app. It checks actual
HTTPS payloads using curl and optionally launches headless Chrome with a
temporary, separate browser profile to verify Facebook and save a screenshot.
The backend port is the internal `SOCKS5 proxy listening` address in the log,
not the public mixed port. This is a developer diagnostic, not an alternate
way to activate the app.

```powershell
cargo run --release --no-default-features --example proxy_probe -- --backend-port PORT --output D:\proxy-proof --chrome "C:\Program Files\Google\Chrome\Application\chrome.exe"
```

## Compatibility and implementation

Old profiles without a `routing` field are translated from their enabled
split-tunnel settings. Country IR now uses bundled data without requiring
an imported JSON file. Old bare domain entries retain their original suffix
semantics. A custom country JSON database overrides only its listed country
codes. Invalid/missing databases or invalid active rules produce a visible
error instead of silently dropping bypass rules. New routing configuration
is included in profile JSON exports.

The mixed HTTP/SOCKS listener is loopback-only. HTTP CONNECT carries the
hostname, fixing the information loss in Windows' SOCKS4 path. Explicit
SOCKS4/4a and SOCKS5 clients use the same router. Direct traffic uses a native
socket; Proxy traffic goes to an internal ephemeral loopback SOCKS listener
backed by the existing rVPN per-flow relay. Disconnect closes both listeners
and their flows and restores the previous Windows proxy settings.

These rules apply to **TCP proxy mode**. TUN continues using its existing
split-tunnel settings. Apps that ignore the Windows system proxy are not
captured. UDP ASSOCIATE is explicitly rejected. SOCKS clients sending only
an IP cannot match domain rules; use HTTP CONNECT or SOCKS5 with remote DNS
when domain policies are required. GeoIP/geosite uses verified saved data
with an embedded offline fallback, documented in [assets/GEODATA.md](assets/GEODATA.md).

## Automatic GeoIP / GeoSite updates

Each Proxy connection first prepares and verifies the internal tunnel, then
checks the latest Loyalsoldier/v2ray-rules-dat release. Windows system proxy
is enabled only after this check finishes and the router has loaded the
selected database pair. Unchanged data is reused without downloading the
databases. Changed GeoIP and GeoSite files must both pass SHA-256 and protobuf
validation before they become active. Cache files persist in
`%LOCALAPPDATA%\rvpn-windows\geodata\`; the distribution remains just the
executable and Wintun DLL. The Connect status card shows the active version,
updates and fallback warnings. If GitHub is unavailable or a download fails,
the last verified pair is retained, or the embedded fallback is used.

To exercise the updater against the real source in a separate cache without
reading profiles or changing Windows settings:

```powershell
cargo run --release --no-default-features --example geodata_update -- --cache D:\geo-update-test --backend-port PORT
```

Omit `--backend-port` for a direct network diagnostic. Unit tests use only
loopback HTTP fixtures and temporary caches, covering ETag reuse, updates,
asset replacement, incomplete downloads, invalid hashes/protobuf and cache repair.

## Validation

```powershell
cargo test --release --no-default-features
cargo build --release
```

`routing_proxy` tests are loopback-only and exercise real DNS packets,
HTTP forward/CONNECT, SOCKS4/5, direct-vs-backend selection and preservation
of destination names, alongside GeoIP/geosite, order, migration and validation.
They do not change the machine's proxy, use saved identities, or connect to
the production server. Production tests remain explicitly ignored.

## فارسی

در صفحهٔ **Connect** حالت **Proxy** را انتخاب کنید و وارد **Routing** شوید.
گزینهٔ **More → Preset: Iran direct** دامنه‌های `.ir`، آی‌پی‌های ایران و شبکه‌های
خصوصی را مستقیم و سایر مقصدها را از پروکسی عبور می‌دهد. برای هر قانون
می‌توانید دامنه، آی‌پی یا کشور تعیین کنید و مسیر **Direct / Proxy / Block**
را انتخاب کنید. با **Add Rule** یا دابل‌کلیک روی سطر وارد ویرایشگر سه‌ستونی
شوید. **Confirm** داخل دیالوگ، ویرایش را موقتاً ثبت می‌کند؛ سپس در پنل اصلی
هم **Confirm** بزنید و اتصال را قطع و وصل کنید. **Cancel** پنل اصلی تغییرات
ذخیره‌نشده را برمی‌گرداند. برای اولویت از **Up / Down / Top / Bottom** استفاده کنید.

کشور، موقعیت آی‌پی مقصد است؛ برای سایت ایرانی با CDN خارجی، یک قانون دامنه
مثل `domain:digikala.com` با مسیر Direct اضافه کنید. انتخاب کشور، کشور سرور
خروجی را تغییر نمی‌دهد. این صفحه مخصوص حالت پروکسی است؛ تنظیمات TUN در
بخش Split tunnel پروفایل باقی مانده است.

پیش از هر اتصال در حالت Proxy، آخرین نسخهٔ GeoIP و GeoSite از همان منبع
Loyalsoldier بررسی و در صورت تغییر دانلود و اعتبارسنجی می‌شود. داده‌ها روی
دیسک ذخیره می‌مانند. اگر بررسی یا دانلود ناموفق باشد، آخرین نسخهٔ سالم یا
دادهٔ داخلی برنامه استفاده می‌شود و وضعیت آن در صفحهٔ Connect دیده می‌شود.
