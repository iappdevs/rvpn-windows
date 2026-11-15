//! Verify the production updater in an explicit, isolated cache. No profile,
//! identity, registry, system-proxy or running-app changes.
use anyhow::{Context, Result};
use std::path::PathBuf;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let value = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
    };
    let root = PathBuf::from(value("--cache").context("--cache is required")?);
    let backend = value("--backend-port")
        .map(|port| format!("127.0.0.1:{port}").parse())
        .transpose()?;
    let report =
        rvpn_windows::geodata::update_cache(&root, backend, |detail| println!("{detail}")).await;
    println!("{}", report.description());
    if let Some(warning) = report.warning {
        anyhow::bail!("{warning}");
    }
    println!(
        "Countries: {}; GeoSite groups: {}",
        rvpn_windows::routing::country_codes().len(),
        rvpn_windows::routing::geosite_groups().len()
    );
    Ok(())
}
