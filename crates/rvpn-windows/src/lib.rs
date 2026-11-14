//! rvpn-windows library — all client functionality. The binary (`main.rs`)
//! is a thin shell; examples and tests link this crate directly.

pub mod app;
pub mod engine;
pub mod identity;
pub mod logging;
pub mod paths;
pub mod platform;
pub mod profile;
pub mod sysproxy;
pub mod tray;
pub mod tundevice;
pub mod winroute;
