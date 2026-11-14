//! Windows resources: the requireAdministrator manifest (the Wintun adapter
//! and route changes need elevation). Embedded in release builds only, so
//! debug builds and `cargo test` binaries run without a UAC prompt.

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let profile = std::env::var("PROFILE").unwrap_or_default();
    if target_os != "windows" || profile != "release" {
        return;
    }
    let mut res = winres::WindowsResource::new();
    res.set_manifest(include_str!("resources/app.manifest"));
    if let Err(e) = res.compile() {
        println!("cargo::warning=winres compile failed: {e}");
    }
}
