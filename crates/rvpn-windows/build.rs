//! Windows resources: the requireAdministrator manifest (the Wintun adapter
//! and route changes need elevation).
//!
//! Gated behind the default `admin-manifest` cargo feature so release/test
//! binaries opt out with `--no-default-features` — without this, `cargo
//! test --release` executables inherit the manifest and Windows refuses to
//! run them from a non-elevated shell (os error 740).

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let admin_manifest = std::env::var("CARGO_FEATURE_ADMIN_MANIFEST").is_ok();
    if target_os != "windows" || !admin_manifest {
        return;
    }
    let mut res = winres::WindowsResource::new();
    res.set_manifest(include_str!("resources/app.manifest"));
    if let Err(e) = res.compile() {
        println!("cargo::warning=winres compile failed: {e}");
    }
}
