//! The egui application: connection screen, profile manager, settings,
//! log view, and the TOFU trust dialogs.

use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};

use eframe::egui;
use eframe::egui::{Align2, Color32, Layout, RichText, Sense, Vec2};

use crate::engine::{EngineEvent, EngineHandle, EnginePhase, EngineSnapshot};
use crate::logging::LogRing;
use crate::platform;
use crate::profile::{AppSettings, Profile, ProfileStore, MAX_PROFILES};
use crate::tray::{Tray, TrayCommand};

const ACCENT: Color32 = Color32::from_rgb(46, 184, 114);
const WARN: Color32 = Color32::from_rgb(235, 175, 44);
const DANGER: Color32 = Color32::from_rgb(214, 74, 74);
const CARD_BG: Color32 = Color32::from_rgb(24, 28, 34);

#[derive(Debug, Clone, Copy, PartialEq)]
enum View {
    Connect,
    Profiles,
    Settings,
    Logs,
}

/// A file-picker request in flight (rfd runs off-thread).
struct Picker {
    purpose: PickerPurpose,
    slug: String,
    receiver: Receiver<Option<(String, String)>>, // (absolute path, contents)
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum PickerPurpose {
    ImportPrekey,
    ImportIdentity,
    ImportProfile,
    ExportProfile,
}

pub struct RvpnApp {
    view: View,
    profiles: Vec<Profile>,
    settings: AppSettings,
    engine: Option<EngineHandle>,
    engine_events: Receiver<EngineEvent>,
    /// Graceful handoff: connect runs on a worker thread, drops the handle
    /// here when done so the UI picks it up.
    engine_slot: Arc<Mutex<Option<EngineHandle>>>,
    connect_thread: Option<std::thread::JoinHandle<()>>,
    snapshot: EngineSnapshot,
    selected_profile: Option<String>,
    engine_log: LogRing,
    tray: Option<Tray>,
    picker: Option<Picker>,
    /// Profile being created/edited.
    editing: Option<Profile>,
    /// Profile slug pending delete confirmation.
    confirm_delete: Option<String>,
    /// `.rvpn` document waiting for the export path pick.
    export_payload: Option<String>,
    /// Pending TOFU decision (mismatch).
    tofu_dialog: Option<(String, String, String)>, // (slug, expected, actual)
    /// Flash message shown at the bottom.
    flash: Option<(String, std::time::Instant, Color32)>,
    force_quit: bool,
    show_window: bool,
}

impl RvpnApp {
    pub fn new(engine_log: LogRing, tray: Option<Tray>) -> Self {
        let profiles = ProfileStore::load().unwrap_or_default();
        let settings = Self::load_settings();
        let selected = profiles
            .iter()
            .find(|p| p.is_default)
            .or_else(|| profiles.first())
            .map(|p| p.slug.clone());
        let (_tx, rx) = mpsc::channel();
        let start_minimized = settings.start_minimized;
        Self {
            view: View::Connect,
            profiles,
            settings,
            engine: None,
            engine_events: rx,
            engine_slot: Arc::new(Mutex::new(None)),
            connect_thread: None,
            snapshot: EngineSnapshot {
                phase: crate::engine::EnginePhase::Idle,
                rx_bytes: 0,
                tx_bytes: 0,
                connected_for_secs: None,
                server_pin: None,
            },
            selected_profile: selected,
            engine_log,
            tray,
            picker: None,
            editing: None,
            confirm_delete: None,
            export_payload: None,
            tofu_dialog: None,
            flash: None,
            force_quit: false,
            show_window: !start_minimized,
        }
    }

    fn load_settings() -> AppSettings {
        AppSettings::load_from_disk()
    }

    /// Slug of the default profile (auto-connect target), if any.
    pub fn default_profile_slug(&self) -> Option<String> {
        self.profiles
            .iter()
            .find(|p| p.is_default)
            .map(|p| p.slug.clone())
    }

    pub fn select_profile(&mut self, slug: &str) {
        if self.profiles.iter().any(|p| p.slug == slug) {
            self.selected_profile = Some(slug.to_string());
        }
    }

    /// Kick off a connect for the currently selected profile (used by
    /// auto-connect at launch).
    pub fn request_connect(&mut self) {
        self.start_connect();
    }

    fn save_settings(&self) {
        let _ = std::fs::write(
            crate::paths::settings_file(),
            serde_json::to_string_pretty(&self.settings).unwrap_or_default(),
        );
    }

    fn flash(&mut self, msg: impl Into<String>, color: Color32) {
        self.flash = Some((msg.into(), std::time::Instant::now(), color));
    }

    fn selected(&self) -> Option<&Profile> {
        self.profiles
            .iter()
            .find(|p| Some(&p.slug) == self.selected_profile.as_ref())
    }

    // ---- engine control ------------------------------------------------------

    fn start_connect(&mut self) {
        let Some(profile) = self.selected().cloned() else {
            self.flash("No profile selected", WARN);
            return;
        };
        if self.engine.as_ref().is_some_and(|e| e.is_active()) {
            return;
        }
        let (tx, rx) = mpsc::channel::<EngineEvent>();
        self.engine_events = rx;
        let slot = self.engine_slot.clone();
        self.connect_thread = Some(
            std::thread::Builder::new()
                .name("rvpn-connect".into())
                .spawn(move || {
                    let handle = EngineHandle::connect(&profile, tx);
                    *slot.lock().unwrap() = Some(handle);
                })
                .expect("failed to spawn connect thread"),
        );
    }

    fn disconnect(&mut self) {
        if let Some(engine) = &self.engine {
            engine.stop();
        }
    }

    // ---- per-frame housekeeping -----------------------------------------------

    fn pump_background(&mut self, ctx: &egui::Context) {
        // Pick up a finished connect attempt's handle.
        if let Some(handle) = self.engine_slot.lock().unwrap().take() {
            self.engine = Some(handle);
            self.connect_thread = None;
        }
        // Drain engine events.
        while let Ok(event) = self.engine_events.try_recv() {
            match event {
                EngineEvent::Phase(p) => {
                    self.snapshot.phase = p.clone();
                    if let Some(tray) = &self.tray {
                        tray.update_phase(&p);
                    }
                    if let EnginePhase::Failed { reason } = &p {
                        self.flash(format!("Disconnected: {reason}"), DANGER);
                    }
                }
                EngineEvent::TofuCaptured { slug, pin } => {
                    if let Some(p) = self.profiles.iter_mut().find(|p| p.slug == slug) {
                        p.server_identity_pin = Some(pin.clone());
                    }
                    let _ = ProfileStore::save(&self.profiles);
                    self.flash("Server identity pinned (TOFU)", ACCENT);
                }
                EngineEvent::TofuMismatch { slug, expected, actual } => {
                    self.tofu_dialog = Some((slug, expected, actual));
                }
                EngineEvent::Readdressed { ip, gateway } => {
                    self.flash(format!("Tunnel address updated: {ip} via {gateway}"), ACCENT);
                }
                EngineEvent::Stopped => {
                    self.snapshot = EngineSnapshot {
                        phase: EnginePhase::Idle,
                        rx_bytes: 0,
                        tx_bytes: 0,
                        connected_for_secs: None,
                        server_pin: None,
                    };
                    self.engine = None;
                    if let Some(tray) = &self.tray {
                        tray.update_phase(&EnginePhase::Idle);
                    }
                }
            }
        }
        // Refresh snapshot while connected.
        if let Some(engine) = &self.engine {
            self.snapshot = engine.snapshot();
        }
        // Tray commands.
        if let Some(tray) = &self.tray {
            for cmd in tray.poll_commands() {
                match cmd {
                    TrayCommand::ShowWindow => self.show_window = true,
                    TrayCommand::ToggleConnection => {
                        if self.snapshot.phase == EnginePhase::Idle
                            || matches!(self.snapshot.phase, EnginePhase::Failed { .. })
                        {
                            self.start_connect();
                        } else {
                            self.disconnect();
                        }
                    }
                    TrayCommand::Quit => {
                        self.disconnect();
                        self.force_quit = true;
                    }
                }
            }
        }
        if !self.show_window {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        } else {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        }
        if self.force_quit {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        // Window title reflects state.
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(match &self.snapshot.phase {
            EnginePhase::Connected { .. } => "R-VPN — Connected".into(),
            EnginePhase::Idle => "R-VPN".into(),
            other => format!("R-VPN — {other:?}"),
        }));
    }

    fn poll_picker(&mut self) {
        let Some(picker) = &self.picker else { return };
        let Ok(result) = picker.receiver.try_recv() else { return };
        let picker = self.picker.take().unwrap();
        match (picker.purpose, result) {
            (PickerPurpose::ImportPrekey, Some((_name, contents))) => {
                match crate::identity::validate_prekey_text(&contents) {
                    Ok(_pin) => {
                        if let Some(p) = self.profiles.iter_mut().find(|p| p.slug == picker.slug) {
                            let _ = ProfileStore::write_prekey(&p.slug, &contents);
                            self.flash("Prekey bundle imported", ACCENT);
                        }
                    }
                    Err(e) => self.flash(format!("Invalid prekey bundle: {e}"), DANGER),
                }
            }
            (PickerPurpose::ImportIdentity, Some((_name, contents))) => {
                if let Some(p) = self.profiles.iter_mut().find(|p| p.slug == picker.slug) {
                    let path = p.identity_path();
                    let _ = std::fs::create_dir_all(p.dir());
                    match std::fs::write(&path, &contents)
                        .map_err(|e| anyhow::anyhow!("{e}"))
                        .and_then(|_| crate::identity::validate_identity_file(&path))
                    {
                        Ok(()) => self.flash("Identity imported", ACCENT),
                        Err(e) => {
                            let _ = std::fs::remove_file(&path);
                            self.flash(format!("Invalid identity: {e}"), DANGER);
                        }
                    }
                }
            }
            (PickerPurpose::ImportProfile, Some((_path, contents))) => {
                match ProfileStore::import(&contents, &self.profiles) {
                    Ok(p) => {
                        self.flash(format!("Profile '{}' imported", p.name), ACCENT);
                        self.selected_profile = Some(p.slug.clone());
                        self.profiles.push(p);
                        let _ = ProfileStore::save(&self.profiles);
                    }
                    Err(e) => self.flash(format!("Import failed: {e}"), DANGER),
                }
            }
            (PickerPurpose::ExportProfile, Some((path, _))) => {
                if let Some(payload) = self.export_payload.take() {
                    match std::fs::write(&path, payload) {
                        Ok(()) => self.flash(format!("Exported to {path}"), ACCENT),
                        Err(e) => self.flash(format!("Export failed: {e}"), DANGER),
                    }
                }
            }
            _ => {}
        }
    }

    fn spawn_picker(&mut self, purpose: PickerPurpose, slug: String, save: Option<String>) {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = if let Some(default_name) = save {
                rfd::FileDialog::new()
                    .set_file_name(default_name)
                    .save_file()
                    .map(|p| (p.display().to_string(), String::new()))
            } else {
                rfd::FileDialog::new()
                    .pick_file()
                    .and_then(|p| {
                        std::fs::read_to_string(&p)
                            .ok()
                            .map(|c| (p.display().to_string(), c))
                    })
            };
            let _ = tx.send(result);
        });
        self.picker = Some(Picker { purpose, slug, receiver: rx });
    }

    // ---- egui ----------------------------------------------------------------

    fn nav_item(&mut self, ui: &mut egui::Ui, view: View, label: &str) {
        let selected = self.view == view;
        let response = ui.add(
            egui::Button::new(
                RichText::new(label)
                    .strong()
                    .color(if selected { ACCENT } else { Color32::PLACEHOLDER }),
            )
            .fill(if selected {
                Color32::from_rgb(20, 34, 28)
            } else {
                Color32::TRANSPARENT
            })
            .min_size(Vec2::new(150.0, 34.0)),
        );
        if response.clicked() {
            self.view = view;
        }
    }
}

impl eframe::App for RvpnApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Closing the window parks the app in the tray (like the macOS
        // menu-bar app); Quit comes from the tray menu.
        if ctx.input(|i| i.viewport().close_requested()) && !self.force_quit {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.show_window = false;
        }
        self.pump_background(ctx);
        self.poll_picker();

        egui::SidePanel::left("nav")
            .resizable(false)
            .exact_width(180.0)
            .frame(egui::Frame::NONE.fill(Color32::from_rgb(15, 18, 22)))
            .show(ctx, |ui| {
                ui.add_space(18.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("R-VPN").strong().size(24.0).color(ACCENT));
                    ui.label(
                        RichText::new("Windows Client")
                            .small()
                            .color(Color32::from_gray(120)),
                    );
                });
                ui.add_space(20.0);
                ui.vertical_centered(|ui| {
                    self.nav_item(ui, View::Connect, "Connect");
                    self.nav_item(ui, View::Profiles, "Profiles");
                    self.nav_item(ui, View::Settings, "Settings");
                    self.nav_item(ui, View::Logs, "Logs");
                    ui.with_layout(Layout::bottom_up(egui::Align::TOP), |ui| {
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new(if platform::is_elevated() {
                                "running as Administrator"
                            } else {
                                "NOT elevated — tunnel needs admin"
                            })
                            .small()
                            .color(if platform::is_elevated() {
                                Color32::from_gray(110)
                            } else {
                                WARN
                            }),
                        );
                    });
                });
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(Color32::from_rgb(18, 21, 26)))
            .show(ctx, |ui| match self.view {
                View::Connect => self.view_connect(ui),
                View::Profiles => self.view_profiles(ui),
                View::Settings => self.view_settings(ui),
                View::Logs => self.view_logs(ui),
            });

        // Bottom flash bar.
        if let Some((msg, at, color)) = &self.flash {
            if at.elapsed().as_secs() < 6 {
                egui::TopBottomPanel::bottom("flash").show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.colored_label(*color, msg.clone());
                    })
                });
            } else {
                self.flash = None;
            }
        }

        self.show_tofu_dialog(ctx);
        self.show_profile_editor(ctx);

        // Keep the UI at ~2 fps when idle, full rate while connecting.
        let running = self.engine.as_ref().is_some_and(|e| e.is_active());
        ctx.request_repaint_after(std::time::Duration::from_millis(if running {
            250
        } else {
            500
        }));
    }
}

// ============================================================================
// Views
// ============================================================================

impl RvpnApp {
    fn view_connect(&mut self, ui: &mut egui::Ui) {
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Connection").strong().size(20.0));
        });
        ui.add_space(12.0);

        // Profile selector.
        egui::ComboBox::from_id_salt("profile")
            .selected_text(
                self.selected()
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| "no profile".into()),
            )
            .width(ui.available_width() - 220.0)
            .show_ui(ui, |ui| {
                for p in &self.profiles {
                    ui.selectable_value(
                        &mut self.selected_profile,
                        Some(p.slug.clone()),
                        format!("{}  —  {}", p.name, p.server_address),
                    );
                }
            });
        ui.add_space(16.0);

        // Status card.
        egui::Frame::NONE
            .fill(CARD_BG)
            .corner_radius(10)
            .inner_margin(egui::Margin::same(20))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                let (state_label, state_color) = match &self.snapshot.phase {
                    EnginePhase::Idle => ("Disconnected", Color32::from_gray(150)),
                    EnginePhase::Starting => ("Starting…", WARN),
                    EnginePhase::Connecting { detail } => (detail.as_str(), WARN),
                    EnginePhase::Connected { .. } => ("Connected", ACCENT),
                    EnginePhase::Failed { .. } => ("Failed", DANGER),
                    EnginePhase::Stopping => ("Stopping…", WARN),
                };
                ui.horizontal(|ui| {
                    status_dot(ui, state_color);
                    ui.label(RichText::new(state_label).size(22.0).strong().color(state_color));
                });
                ui.add_space(10.0);

                if let EnginePhase::Connected { ip, gateway, server } = &self.snapshot.phase {
                    grid_row(ui, "Tunnel IP", ip);
                    grid_row(ui, "Gateway", gateway);
                    grid_row(ui, "Server", server);
                    if let Some(secs) = self.snapshot.connected_for_secs {
                        grid_row(ui, "Uptime", &format_duration(secs));
                    }
                    grid_row(
                        ui,
                        "Traffic",
                        &format!("↓ {}   ↑ {}", fmt_bytes(self.snapshot.rx_bytes), fmt_bytes(self.snapshot.tx_bytes)),
                    );
                    if let Some(pin) = &self.snapshot.server_pin {
                        grid_row(ui, "Server pin", &pin[..44.min(pin.len())]);
                    }
                } else if let EnginePhase::Failed { reason } = &self.snapshot.phase {
                    ui.label(RichText::new(reason).color(DANGER));
                }
            });
        ui.add_space(20.0);

        // Connect / Disconnect button.
        let active = self.engine.as_ref().is_some_and(|e| e.is_active())
            && !matches!(self.snapshot.phase, EnginePhase::Stopping);
        let (label, color) = if active {
            ("Disconnect", DANGER)
        } else {
            ("Connect", ACCENT)
        };
        let btn = egui::Button::new(RichText::new(label).size(18.0).strong().color(Color32::BLACK))
            .fill(color)
            .corner_radius(8)
            .min_size(Vec2::new(220.0, 48.0));
        if ui.add(btn).clicked() {
            if active {
                self.disconnect();
            } else {
                self.start_connect();
            }
        }
        if !platform::is_elevated() {
            ui.add_space(8.0);
            ui.label(
                RichText::new(
                    "TUN mode needs Administrator rights — \
                     right-click rvpn-windows.exe and choose “Run as administrator”.",
                )
                .small()
                .color(WARN),
            );
        }
    }

    fn view_profiles(&mut self, ui: &mut egui::Ui) {
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Profiles").strong().size(20.0));
            ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Import .rvpn…").clicked() {
                    self.spawn_picker(PickerPurpose::ImportProfile, String::new(), None);
                }
                if ui
                    .add_enabled(self.profiles.len() < MAX_PROFILES, egui::Button::new("+ New"))
                    .clicked()
                {
                    self.editing = Some(Profile::new("New profile"));
                }
            });
        });
        ui.add_space(10.0);

        if self.profiles.is_empty() {
            ui.label(
                RichText::new(
                    "No profiles yet. Create one, then generate an identity and import \
                     the server's prekey-bundle.json.",
                )
                .color(Color32::from_gray(140)),
            );
            return;
        }

        // Clone the list so UI closures can mutate `self` freely while the
        // per-profile card borrows profile data.
        let profiles = self.profiles.clone();
        egui::ScrollArea::vertical().show(ui, |ui| {
            for p in &profiles {
                let selected = Some(&p.slug) == self.selected_profile.as_ref();
                egui::Frame::NONE
                    .fill(if selected {
                        Color32::from_rgb(20, 34, 28)
                    } else {
                        CARD_BG
                    })
                    .corner_radius(8)
                    .inner_margin(egui::Margin::same(14))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.set_width(ui.available_width());
                            ui.vertical(|ui| {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(&p.name).strong().size(16.0));
                                    if p.is_default {
                                        ui.label(RichText::new("★ default").small().color(ACCENT));
                                    }
                                });
                                ui.label(
                                    RichText::new(&p.server_address)
                                        .small()
                                        .color(Color32::from_gray(130)),
                                );
                                ui.horizontal(|ui| {
                                    badge(ui, p.has_identity(), "identity");
                                    badge(ui, p.has_prekey(), "prekey");
                                    badge(ui, p.server_identity_pin.is_some(), "pinned");
                                });
                            });
                            ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.button("Delete").clicked() {
                                    self.confirm_delete = Some(p.slug.clone());
                                }
                                if ui.button("Export…").clicked() {
                                    if let Ok(doc) = p.export(false) {
                                        self.spawn_picker(
                                            PickerPurpose::ExportProfile,
                                            String::new(),
                                            Some(format!("{}.rvpn", p.slug)),
                                        );
                                        self.export_payload = Some(doc);
                                    }
                                }
                                if ui.button("Edit").clicked() {
                                    self.editing = Some(p.clone());
                                }
                                if ui
                                    .selectable_label(selected, "Use")
                                    .clicked()
                                {
                                    self.selected_profile = Some(p.slug.clone());
                                }
                            });
                        });
                    });
                ui.add_space(8.0);
            }
        });

        // Delete confirmation dialog.
        if let Some(slug) = self.confirm_delete.clone() {
            egui::Window::new("Delete profile?")
                .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
                .resizable(false)
                .show(ui.ctx(), |ui| {
                    ui.label(format!(
                        "This removes the profile and its identity key from this computer."
                    ));
                    ui.horizontal(|ui| {
                        if ui.button("Delete").clicked() {
                            if let Some(p) = self.profiles.iter().find(|p| p.slug == slug) {
                                let _ = ProfileStore::delete(p);
                            }
                            self.profiles.retain(|p| p.slug != slug);
                            if self.selected_profile.as_deref() == Some(slug.as_str()) {
                                self.selected_profile = self.profiles.first().map(|p| p.slug.clone());
                            }
                            let _ = ProfileStore::save(&self.profiles);
                            self.confirm_delete = None;
                        }
                        if ui.button("Cancel").clicked() {
                            self.confirm_delete = None;
                        }
                    });
                });
        }
    }

    fn view_settings(&mut self, ui: &mut egui::Ui) {
        ui.add_space(10.0);
        ui.label(RichText::new("Settings").strong().size(20.0));
        ui.add_space(14.0);

        let mut changed = false;
        egui::Frame::NONE
            .fill(CARD_BG)
            .corner_radius(10)
            .inner_margin(egui::Margin::same(18))
            .show(ui, |ui| {
                ui.set_width(ui.available_width().min(560.0));
                changed |= ui
                    .checkbox(&mut self.settings.auto_connect, "Auto-connect default profile at launch")
                    .changed();
                changed |= ui
                    .checkbox(&mut self.settings.start_minimized, "Start minimized to tray")
                    .changed();
                if ui
                    .checkbox(&mut self.settings.launch_at_startup, "Launch at Windows startup")
                    .changed()
                {
                    changed = true;
                    if let Err(e) = platform::set_launch_at_startup(self.settings.launch_at_startup) {
                        self.flash(format!("Startup registration failed: {e}"), DANGER);
                    }
                }
            });
        if changed {
            self.save_settings();
        }
        ui.add_space(16.0);
        ui.label(
            RichText::new(
                "Traffic is end-to-end encrypted (X3DH + Double Ratchet) and looks like \
                 ordinary HTTPS over WebSocket/TLS 1.3. The local DNS proxy blocks ads and \
                 resolves via DoH through the tunnel.",
            )
            .small()
            .color(Color32::from_gray(130)),
        );
    }

    fn view_logs(&mut self, ui: &mut egui::Ui) {
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Logs").strong().size(20.0));
            ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Clear").clicked() {
                    self.engine_log.clear();
                }
            });
        });
        ui.add_space(8.0);
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Frame::NONE
                    .fill(Color32::from_rgb(12, 14, 17))
                    .corner_radius(8)
                    .inner_margin(egui::Margin::same(12))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.style_mut().override_font_id =
                            Some(egui::FontId::monospace(12.0));
                        for entry in self.engine_log.tail(500) {
                            let color = match entry.level {
                                tracing::Level::ERROR => DANGER,
                                tracing::Level::WARN => WARN,
                                tracing::Level::INFO => Color32::from_gray(180),
                                _ => Color32::from_gray(130),
                            };
                            ui.colored_label(color, entry.formatted());
                        }
                    });
            });
    }

    // ---- dialogs ---------------------------------------------------------------

    fn show_tofu_dialog(&mut self, ctx: &egui::Context) {
        let Some((slug, expected, actual)) = self.tofu_dialog.clone() else {
            return;
        };
        egui::Window::new("Server identity changed")
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .resizable(false)
            .collapsible(false)
            .show(ctx, |ui| {
                ui.set_width(460.0);
                ui.label(
                    RichText::new(
                        "The server presented a different identity key than the one pinned \
                         in this profile. This can mean the operator rotated the key — or \
                         that you are being intercepted.",
                    )
                    .color(WARN),
                );
                ui.add_space(8.0);
                ui.monospace(format!("expected: {expected}"));
                ui.monospace(format!("actual:   {actual}"));
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.button("Trust new identity").clicked() {
                        if let Some(p) = self.profiles.iter_mut().find(|p| p.slug == slug) {
                            p.server_identity_pin = Some(actual.clone());
                        }
                        let _ = ProfileStore::save(&self.profiles);
                        self.tofu_dialog = None;
                        self.flash("Server pin updated", ACCENT);
                    }
                    if ui.button("Cancel").clicked() {
                        self.tofu_dialog = None;
                    }
                });
            });
    }

    fn show_profile_editor(&mut self, ctx: &egui::Context) {
        let Some(mut editing) = self.editing.clone() else { return };
        let mut open = true;
        egui::Window::new(if self.profiles.iter().any(|p| p.slug == editing.slug) {
            "Edit profile"
        } else {
            "New profile"
        })
        .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
        .resizable(false)
        .open(&mut open)
        .show(ctx, |ui| {
            ui.set_width(560.0);
            egui::Grid::new("editor")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Name");
                    ui.text_edit_singleline(&mut editing.name);
                    ui.end_row();

                    ui.label("Server");
                    ui.add(
                        egui::TextEdit::singleline(&mut editing.server_address)
                            .hint_text("wss://your-server.com:443/api/v1/ws/tun"),
                    );
                    ui.end_row();

                    ui.label("SNI override");
                    ui.add_enabled(
                        false,
                        egui::TextEdit::singleline(
                            editing.sni_hostname.get_or_insert_with(String::new),
                        )
                        .hint_text("defaults to the server host"),
                    );
                    ui.end_row();

                    ui.label("DNS (fallback)");
                    let mut dns = editing.dns_servers.join(", ");
                    ui.text_edit_singleline(&mut dns);
                    editing.dns_servers = dns
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    ui.end_row();

                    ui.label("MTU");
                    ui.add(egui::DragValue::new(&mut editing.mtu).range(1200..=1500));
                    ui.end_row();

                    ui.label("Bypass CIDRs");
                    let mut bypass = editing.bypass_networks.join(", ");
                    ui.text_edit_singleline(&mut bypass)
                        .on_hover_text("e.g. 192.168.0.0/16, 10.0.0.0/8");
                    editing.bypass_networks = bypass
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    ui.end_row();
                });

            ui.add_space(6.0);
            ui.checkbox(&mut editing.split_tunnel_enabled, "Split tunnel (bypass countries)");
            if editing.split_tunnel_enabled {
                let countries = rvpn_mobile::rvpn_split_tunnel::supported_countries();
                ui.horizontal(|ui| {
                    ui.label("Bypass countries:");
                    for code in countries {
                        let on = editing.builtin_bypass_countries.iter().any(|c| c == code);
                        if ui
                            .selectable_label(on, RichText::new(*code).small())
                            .clicked()
                        {
                            if on {
                                editing.builtin_bypass_countries.retain(|c| c != code);
                            } else {
                                editing.builtin_bypass_countries.push(code.to_string());
                            }
                        }
                    }
                });
            }
            ui.checkbox(&mut editing.is_default, "Default profile (auto-connect target)");

            ui.separator();
            ui.horizontal(|ui| {
                ui.label("Identity key:");
                if editing.has_identity() {
                    ui.label(RichText::new("✓ loaded").color(ACCENT).small());
                } else {
                    if ui.button("Generate").clicked() {
                        let dir = crate::paths::profile_dir(&editing.slug);
                        let _ = std::fs::create_dir_all(&dir);
                        match crate::identity::generate_identity(&dir.join("identity.key")) {
                            Ok(()) => self.flash("Identity generated", ACCENT),
                            Err(e) => self.flash(format!("{e}"), DANGER),
                        }
                    }
                    if ui.button("Import…").clicked() {
                        self.spawn_picker(PickerPurpose::ImportIdentity, editing.slug.clone(), None);
                    }
                }
                ui.separator();
                ui.label("Prekey bundle:");
                if editing.has_prekey() {
                    ui.label(RichText::new("✓ loaded").color(ACCENT).small());
                } else if ui.button("Import…").clicked() {
                    self.spawn_picker(PickerPurpose::ImportPrekey, editing.slug.clone(), None);
                }
            });

            ui.add_space(10.0);
            ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Save").clicked() {
                    match editing.validate() {
                        Ok(()) | Err(_) => {
                            // allow saving incomplete drafts; validation happens on connect
                            editing.slug = crate::profile::slugify(&editing.name);
                            if let Some(existing) =
                                self.profiles.iter_mut().find(|p| p.slug == editing.slug)
                            {
                                // keep identity/prekey files when renaming over same slug
                                *existing = editing.clone();
                            } else {
                                let _ = std::fs::create_dir_all(editing.dir());
                                if editing.is_default {
                                    for p in self.profiles.iter_mut() {
                                        p.is_default = false;
                                    }
                                }
                                self.profiles.push(editing.clone());
                            }
                            if editing.is_default {
                                for p in self.profiles.iter_mut() {
                                    p.is_default = p.slug == editing.slug;
                                }
                            }
                            let _ = ProfileStore::save(&self.profiles);
                            self.selected_profile = Some(editing.slug);
                            self.editing = None;
                        }
                    }
                }
                if ui.button("Cancel").clicked() {
                    self.editing = None;
                }
            });
        });
        if !open {
            self.editing = None;
        }
    }
}

// ============================================================================
// Small widgets
// ============================================================================

fn status_dot(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
    ui.painter()
        .circle_filled(rect.center(), 6.0, color);
}

fn grid_row(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.set_width(ui.available_width());
        ui.label(
            RichText::new(key)
                .small()
                .color(Color32::from_gray(120)),
        );
        ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(RichText::new(value).monospace().small().color(Color32::from_gray(210)));
        });
    });
}

fn badge(ui: &mut egui::Ui, ok: bool, label: &str) {
    let (mark, color) = if ok {
        ("✓", ACCENT)
    } else {
        ("○", Color32::from_gray(110))
    };
    ui.label(RichText::new(format!("{mark} {label}")).small().color(color));
}

fn fmt_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn format_duration(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h {m}m {s}s")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}
