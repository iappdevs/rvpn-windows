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
    // The application icon, drawn by scripts/make_icon.py. Absolute: build
    // scripts run from the package directory.
    let icon = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../../assets/app.ico");
    res.set_icon(&icon.to_string_lossy());
    if let Err(e) = res.compile() {
        // A missing manifest means the app runs without the Administrator
        // rights Wintun and the route table need — never ship that quietly.
        panic!("winres compile failed: {e}");
    }
}
