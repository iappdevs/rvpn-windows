//! rvpn-windows — the R-VPN client for Windows. See `lib.rs` for the
//! library surface; this binary only wires up logging, the tray, and the
//! egui window.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;

fn main() -> eframe::Result<()> {
    // Single instance: if another copy is already running (usually parked in
    // the tray), surface its window instead of starting a second one.
    let Some(_instance) = rvpn_windows::platform::SingleInstance::try_acquire() else {
        rvpn_windows::platform::activate_running_instance();
        return Ok(());
    };

    rvpn_windows::paths::ensure_dirs().expect("failed to create %APPDATA% directories");

    // Self-healing: clean NRPT rules a crashed/killed previous run may have
    // left behind (they hold the system resolver hostage after disconnect),
    // and restore the system proxy if a proxy session died uncleanly.
    rvpn_windows::winroute::sweep_stale_state();
    rvpn_windows::sysproxy::sweep_stale_system_proxy();

    // Logging: GUI ring + capped file. Set RVPN_LOG_LEVEL=debug|trace for
    // engine diagnostics (same variable the upstream apps honour).
    let ring = rvpn_windows::logging::LogRing::default();
    rvpn_windows::logging::init(&ring, Some(rvpn_windows::paths::log_dir().join("rvpn-windows.log")));
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "rvpn-windows starting");

    // The tray must be created before the GUI loop so its Win32 message
    // window exists; on failure we still run as a plain window app.
    let tray = rvpn_windows::tray::Tray::new(&rvpn_windows::engine::EnginePhase::Idle).ok();

    let icon = window_icon();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 640.0])
            .with_min_inner_size([780.0, 540.0])
            .with_icon(std::sync::Arc::new(icon))
            .with_title("R-VPN"),
        ..Default::default()
    };

    let mut app = rvpn_windows::app::RvpnApp::new(ring, tray);

    // Auto-connect the default profile if requested.
    let settings = rvpn_windows::profile::AppSettings::load_from_disk();
    if settings.auto_connect {
        if let Some(default) = app.default_profile_slug() {
            app.select_profile(&default);
            app.request_connect();
        }
    }

    eframe::run_native(
        "rvpn-windows",
        options,
        Box::new(move |cc| {
            style(cc);
            Ok(Box::new(app))
        }),
    )
}

fn style(cc: &eframe::CreationContext<'_>) {
    use egui::{CornerRadius, Style, Visuals};
    let mut style = Style::default();
    style.visuals = Visuals::dark();
    style.visuals.panel_fill = egui::Color32::from_rgb(18, 21, 26);
    style.visuals.window_fill = egui::Color32::from_rgb(24, 28, 34);
    style.visuals.extreme_bg_color = egui::Color32::from_rgb(12, 14, 17);
    style.visuals.faint_bg_color = egui::Color32::from_rgb(24, 28, 34);
    style.visuals.selection.bg_fill = egui::Color32::from_rgb(20, 34, 28);
    style.visuals.selection.stroke.color = egui::Color32::from_rgb(46, 184, 114);
    style.visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(24, 28, 34);
    style.visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(30, 35, 42);
    style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(36, 42, 51);
    style.visuals.widgets.active.bg_fill = egui::Color32::from_rgb(20, 34, 28);
    style.visuals.window_corner_radius = CornerRadius::same(10);
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    cc.egui_ctx.set_style(style);
}

fn window_icon() -> egui::IconData {
    // Same procedural shield as the tray icon, in the connected-green accent.
    let (rgba, w, h) = rvpn_windows::tray::icon_rgba([46, 184, 114]);
    egui::IconData {
        rgba,
        width: w,
        height: h,
    }
}
