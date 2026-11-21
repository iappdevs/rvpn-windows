//! The egui application: connection screen, profile manager, settings,
//! log view, and the TOFU trust dialogs.

use crate::ui::{self as design, Icon, BG, BORDER, MUTED, SURFACE, TEXT};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};

use eframe::egui;
use eframe::egui::{Align2, Color32, Layout, RichText, Sense, Vec2};

use crate::engine::{EngineEvent, EngineHandle, EnginePhase, EngineSnapshot};
use crate::logging::LogRing;
use crate::platform;
use crate::profile::{AppSettings, ConnMode, Profile, ProfileStore, MAX_PROFILES};
use crate::tray::{Tray, TrayCommand};

const ACCENT: Color32 = design::ACCENT;
const WARN: Color32 = Color32::from_rgb(235, 175, 44);
const DANGER: Color32 = Color32::from_rgb(214, 74, 74);

#[derive(Debug, Clone, Copy, PartialEq)]
enum View {
    Connect,
    Profiles,
    Routing,
    Settings,
    Logs,
}

/// Background messages from the update worker.
enum UpdateMsg {
    Info(crate::updater::ReleaseInfo),
    Failed(String),
    /// Download+install finished; carry the new exe to relaunch on quit.
    Installed(std::path::PathBuf),
}

#[derive(Default, Clone)]
enum UpdateState {
    #[default]
    Idle,
    Checking,
    Available(Box<crate::updater::ReleaseInfo>),
    Downloading,
    /// Installed; quit in progress, relaunch fires on shutdown-complete.
    RelaunchOnQuit(std::path::PathBuf),
    Failed(String),
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
    ImportIpDb,
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
    connect_cancel: Arc<AtomicBool>,
    geodata_status: Option<(String, bool)>,
    snapshot: EngineSnapshot,
    selected_profile: Option<String>,
    routing_draft: Option<crate::routing_ui::RoutingDraft>,
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
    /// Self-update state (checked in the background at launch).
    update: UpdateState,
    update_rx: Option<std::sync::mpsc::Receiver<UpdateMsg>>,
    update_relaunched: bool,
    /// After the launch check, further checks/failures are silent unless manual.
    auto_update_silent: bool,
    editor_tab: usize,
    settings_tab: usize,
    log_filter: String,
    editor_buffers: std::collections::BTreeMap<String, String>,
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
        let start_minimized = settings.start_minimized && tray.is_some();
        Self {
            view: View::Connect,
            profiles,
            settings,
            engine: None,
            engine_events: rx,
            engine_slot: Arc::new(Mutex::new(None)),
            connect_thread: None,
            connect_cancel: Arc::new(AtomicBool::new(false)),
            geodata_status: None,
            snapshot: EngineSnapshot {
                phase: crate::engine::EnginePhase::Idle,
                rx_bytes: 0,
                tx_bytes: 0,
                connected_for_secs: None,
                server_pin: None,
            },
            selected_profile: selected,
            routing_draft: None,
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
            update: UpdateState::Idle,
            update_rx: None,
            update_relaunched: false,
            auto_update_silent: false,
            editor_tab: 0,
            settings_tab: 0,
            log_filter: String::new(),
            editor_buffers: std::collections::BTreeMap::new(),
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

    fn save_settings(&mut self) {
        let result = (|| -> anyhow::Result<()> {
            use std::io::Write;
            let path = crate::paths::settings_file();
            std::fs::create_dir_all(path.parent().unwrap())?;
            let mut file = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
            file.write_all(&serde_json::to_vec_pretty(&self.settings)?)?;
            file.as_file().sync_all()?;
            file.persist(path).map_err(|e| e.error)?;
            Ok(())
        })();
        if let Err(error) = result {
            self.flash(format!("Could not save settings: {error}"), DANGER);
        }
    }

    fn flash(&mut self, msg: impl Into<String>, color: Color32) {
        self.flash = Some((msg.into(), std::time::Instant::now(), color));
    }

    /// Export the individual files a mobile rVPN app needs (Android / iOS /
    /// macOS): the prekey bundle JSON and optionally the identity key,
    /// alongside a step-by-step instructions file. The .rvpn container is
    /// Windows-specific; these raw files are what the mobile profile editor
    /// consumes directly.
    fn share_for_mobile(&mut self, profile: &Profile) {
        let dir = rfd::FileDialog::new()
            .set_title("Choose where to save the mobile files")
            .save_file();

        let Some(target) = dir else { return };
        let target = if target.extension().is_some() {
            target
        } else {
            target.with_extension("") // treat as directory
        };
        let folder = target.with_file_name(format!("{}-mobile", profile.slug));
        if let Err(e) = std::fs::create_dir_all(&folder) {
            self.flash(format!("Cannot create folder: {e}"), DANGER);
            return;
        }

        // 1. Prekey bundle — universal JSON, identical format on all platforms.
        let prekey_src = profile.prekey_path();
        let prekey = match std::fs::read_to_string(&prekey_src) {
            Ok(p) => p,
            Err(e) => {
                self.flash(format!("Cannot read prekey bundle: {e}"), DANGER);
                return;
            }
        };
        if let Err(e) = std::fs::write(folder.join("prekey-bundle.json"), &prekey) {
            self.flash(format!("Cannot write prekey: {e}"), DANGER);
            return;
        }

        // 2. Identity key (optional — the mobile app can generate its own).
        let identity_copied = profile
            .identity_path()
            .is_file()
            .then(|| std::fs::copy(profile.identity_path(), folder.join("identity.key")).is_ok())
            .unwrap_or(false);

        // 3. Instructions.
        let instructions = format!(
            "R-VPN Mobile Setup — {}\n\
             ================================\n\n\
             Send these files to your phone (Telegram, email, cloud drive…), then:\n\n\
             ANDROID / iOS:\n\
             1. Open the R-VPN app\n\
             2. Tap + to create a profile\n\
             3. Server Address: {}\n\
             4. Tap 'Import Prekey' and select prekey-bundle.json\n\
             5. Tap 'Generate Identity' (creates a new key for this device)\n\
             6. Save and connect\n\n\
             OPTIONAL — reuse this device's identity:\n\
             Instead of Generate, import the identity.key file.\n\
             (Each device normally generates its own identity; sharing is safe\n\
             but means both devices present the same public key.)\n\n\
             macOS:\n\
             Profiles → Import .rvpn if you have one, or use the same manual steps.\n\n\
             Server pin (TOFU): {}\n\
             This is the server's identity fingerprint. On first connect the app\n\
             captures it automatically. If you ever see a different pin, the server\n\
             may have been replaced — verify before trusting.\n",
            profile.name,
            profile.server_address,
            profile.server_identity_pin.as_deref().unwrap_or("(not pinned yet)"),
        );
        let _ = std::fs::write(folder.join("README.txt"), instructions);

        self.flash(
            format!(
                "Mobile files saved to {} — send them to your phone",
                folder.display()
            ),
            ACCENT,
        );
    }

    /// The update card — shown on the Connect page when a new release is
    /// available, and in Settings for a manual check.
    fn update_card(&mut self, ui: &mut egui::Ui) {
        match &self.update {
            UpdateState::Available(info) => {
                let info = info.clone();
                design::card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("⬆").size(18.0).color(ACCENT));
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new(format!("Update available — {}", info.tag))
                                    .strong(),
                            );
                            let notes: String = info
                                .body
                                .lines()
                                .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
                                .take(4)
                                .collect::<Vec<_>>()
                                .join(" · ");
                            if !notes.is_empty() {
                                ui.label(
                                    RichText::new(notes)
                                        .small()
                                        .color(Color32::from_gray(140)),
                                );
                            }
                        });
                        ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Later").clicked() {
                                self.update = UpdateState::Idle;
                                self.auto_update_silent = true;
                            }
                            let btn = egui::Button::new(
                                RichText::new("Update & restart").strong().color(Color32::BLACK),
                            )
                            .fill(ACCENT);
                            if ui.add(btn).clicked() {
                                self.start_update_install();
                            }
                        });
                    });
                });
            }
            UpdateState::Downloading => {
                design::card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Downloading update… the app restarts when it's ready.");
                    });
                });
            }
            UpdateState::RelaunchOnQuit(_) => {
                design::card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Update installed — restarting…");
                    });
                });
            }
            UpdateState::Failed(e) => {
                let e = e.clone();
                design::card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(RichText::new("Update failed").strong().color(DANGER));
                            ui.label(RichText::new(e).small().color(Color32::from_gray(140)));
                        });
                        ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Retry").clicked() {
                                self.update = UpdateState::Idle;
                                self.auto_update_silent = true;
                                self.start_update_check();
                            }
                        });
                    });
                });
            }
            UpdateState::Checking => {
                design::card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Checking for updates…");
                    });
                });
            }
            UpdateState::Idle => {
                design::card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!(
                                "Version {} — updates download from GitHub releases.",
                                env!("CARGO_PKG_VERSION")
                            ))
                            .small()
                            .color(Color32::from_gray(130)),
                        );
                        ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Check for updates").clicked() {
                                self.auto_update_silent = false;
                                self.start_update_check();
                            }
                        });
                    });
                });
            }
        }
    }

    // ---- self-update -----------------------------------------------------------

    /// Kick off a background release check (skipped in debug builds and
    /// while another one is running).
    fn start_update_check(&mut self) {
        if cfg!(debug_assertions)
            || self.update_rx.is_some()
            || !matches!(self.update, UpdateState::Idle)
        {
            return;
        }
        let (tx, rx) = mpsc::channel::<UpdateMsg>();
        self.update_rx = Some(rx);
        self.update = UpdateState::Checking;
        std::thread::Builder::new()
            .name("rvpn-update-check".into())
            .spawn(move || {
                // Let the UI (and the tunnel) come up first.
                std::thread::sleep(std::time::Duration::from_secs(2));
                match crate::updater::fetch_latest() {
                    Ok(info) => {
                        let _ = tx.send(UpdateMsg::Info(info));
                    }
                    Err(e) => {
                        let _ = tx.send(UpdateMsg::Failed(format!("{e:#}")));
                    }
                }
            })
            .expect("failed to spawn update check");
    }

    /// Non-blocking poll of the update worker + the auto-check trigger.
    fn pump_update(&mut self) {
        let Some(rx) = self.update_rx.take() else {
            return;
        };
        {
            let mut done = false;
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    UpdateMsg::Info(info) => {
                        let newer = crate::updater::is_newer(
                            &info.tag,
                            env!("CARGO_PKG_VERSION"),
                        );
                        if newer {
                            tracing::info!(tag = %info.tag, "update available");
                            self.update = UpdateState::Available(Box::new(info));
                        } else {
                            self.update = UpdateState::Idle;
                            if !self.auto_update_silent {
                                self.flash("You are on the latest version", ACCENT);
                            }
                        }
                        done = true;
                    }
                    UpdateMsg::Failed(e) => {
                        tracing::debug!(error = %e, "update check failed");
                        self.update = UpdateState::Idle;
                        if !self.auto_update_silent {
                            self.flash(format!("Update check failed: {e}"), WARN);
                        }
                        done = true;
                    }
                    UpdateMsg::Installed(path) => {
                        // Files are in place; quit and relaunch at the end.
                        self.update = UpdateState::RelaunchOnQuit(path);
                        self.request_quit();
                        done = true;
                    }
                }
            }
            if done {
                self.update_rx = None;
                self.auto_update_silent = true; // later checks are manual
            }
        }
    }

    /// Download + install the pending release in the background.
    fn start_update_install(&mut self) {
        let UpdateState::Available(info) = self.update.clone() else {
            return;
        };
        self.update = UpdateState::Downloading;
        let url = info.url.clone();
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()));
        let Some(exe_dir) = exe_dir else {
            self.update = UpdateState::Failed("cannot locate the app folder".into());
            return;
        };
        let (tx, rx) = mpsc::channel::<UpdateMsg>();
        self.update_rx = Some(rx);
        std::thread::Builder::new()
            .name("rvpn-update-install".into())
            .spawn(move || {
                let msg = match crate::updater::download_and_install(&url, &exe_dir) {
                    Ok(path) => UpdateMsg::Installed(path),
                    Err(e) => UpdateMsg::Failed(format!("{e:#}")),
                };
                let _ = tx.send(msg);
            })
            .expect("failed to spawn update install");
    }

    fn selected(&self) -> Option<&Profile> {
        self.profiles
            .iter()
            .find(|p| Some(&p.slug) == self.selected_profile.as_ref())
    }

    // ---- engine control ------------------------------------------------------

    fn start_connect(&mut self) {
        if self.connect_thread.is_some() {
            return;
        }
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
        self.connect_cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.connect_cancel.clone();
        self.connect_thread = Some(
            std::thread::Builder::new()
                .name("rvpn-connect".into())
                .spawn(move || {
                    let handle = EngineHandle::connect_cancellable(&profile, tx, cancel);
                    *slot.lock().unwrap() = Some(handle);
                })
                .expect("failed to spawn connect thread"),
        );
    }

    fn disconnect(&mut self) {
        self.connect_cancel.store(true, Ordering::SeqCst);
        if let Some(engine) = &self.engine {
            engine.stop();
        }
    }

    fn request_quit(&mut self) {
        self.force_quit = true;
        self.show_window = true;
        self.disconnect();
    }

    fn shutdown_complete(&self) -> bool {
        self.connect_thread.is_none()
            && self
                .engine
                .as_ref()
                .is_none_or(|engine| engine.is_stopped())
    }

    // ---- per-frame housekeeping -----------------------------------------------

    fn pump_background(&mut self, ctx: &egui::Context) {
        self.pump_update();
        // Join before accepting the result. A panicked worker must not strand
        // the UI in Connecting or leave its Windows proxy behind.
        if self
            .connect_thread
            .as_ref()
            .is_some_and(|worker| worker.is_finished())
        {
            let result = self.connect_thread.take().unwrap().join();
            self.engine = self.engine_slot.lock().unwrap().take();
            if result.is_err() {
                crate::sysproxy::restore_system_proxy();
                self.snapshot.phase=EnginePhase::Failed {reason:"Connection worker stopped unexpectedly. Windows proxy settings were restored.".into()};
            }
        }
        if (self.force_quit || self.connect_cancel.load(Ordering::SeqCst))
            && self.engine.as_ref().is_some_and(|e| !e.is_stopped())
            && !matches!(self.snapshot.phase, EnginePhase::Stopping)
        {
            self.disconnect();
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
                EngineEvent::TofuMismatch {
                    slug,
                    expected,
                    actual,
                } => {
                    self.tofu_dialog = Some((slug, expected, actual));
                }
                EngineEvent::Readdressed { ip, gateway } => {
                    self.flash(
                        format!("Tunnel address updated: {ip} via {gateway}"),
                        ACCENT,
                    );
                }
                EngineEvent::Notice(msg) => {
                    self.flash(msg, WARN);
                }
                EngineEvent::GeoDataStatus {
                    description,
                    warning,
                } => {
                    self.geodata_status = Some((description, warning));
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
                        self.request_quit();
                    }
                }
            }
        }
        if !self.show_window {
            // Win32 (not ViewportCommand) — the egui loop can stall while the
            // window is hidden, leaving a Visible(true) forever unprocessed.
            crate::platform::hide_main_window();
        } else {
            // Visible-check only — NEVER SetForegroundWindow here: a per-frame
            // foreground grab while another app holds focus gets denied and
            // flashes our taskbar button orange.
            crate::platform::ensure_window_visible();
        }
        if self.force_quit && self.shutdown_complete() {
            // Update installed: relaunch the new exe (elevated) right before exit.
            if let UpdateState::RelaunchOnQuit(path) = &self.update {
                if !self.update_relaunched {
                    self.update_relaunched = true;
                    if !crate::updater::relaunch(path) {
                        tracing::error!("relaunch of the updated exe failed");
                    }
                }
            }
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
        let Ok(result) = picker.receiver.try_recv() else {
            return;
        };
        let picker = self.picker.take().unwrap();
        match (picker.purpose, result) {
            (PickerPurpose::ImportPrekey, Some((_name, contents))) => {
                let result = crate::identity::validate_prekey_text(&contents)
                    .and_then(|_| ProfileStore::write_prekey(&picker.slug, &contents));
                match result {
                    Ok(_) => self.flash("Server bundle imported", ACCENT),
                    Err(error) => self.flash(format!("Invalid server bundle: {error}"), DANGER),
                }
            }
            (PickerPurpose::ImportIdentity, Some((_name, contents))) => {
                // Validate a temporary file before replacing an existing identity.
                let result = (|| -> anyhow::Result<()> {
                    let dir = crate::paths::profile_dir(&picker.slug);
                    std::fs::create_dir_all(&dir)?;
                    use std::io::Write;
                    let mut staged = tempfile::NamedTempFile::new_in(&dir)?;
                    staged.write_all(contents.as_bytes())?;
                    staged.as_file().sync_all()?;
                    crate::identity::validate_identity_file(staged.path())?;
                    staged
                        .persist(dir.join("identity.key"))
                        .map_err(|e| e.error)?;
                    Ok(())
                })();
                match result {
                    Ok(()) => self.flash("Identity imported", ACCENT),
                    Err(error) => self.flash(format!("Invalid identity: {error}"), DANGER),
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
            (PickerPurpose::ImportIpDb, Some((_path, contents))) => {
                let result = (|| -> anyhow::Result<()> {
                    let db: std::collections::HashMap<String, Vec<String>> =
                        serde_json::from_str(&contents)?;
                    anyhow::ensure!(!db.is_empty(), "Empty IP database");
                    for networks in db.values() {
                        for network in networks {
                            network.parse::<ip_network::IpNetwork>()?;
                        }
                    }
                    let dir = crate::paths::profile_dir(&picker.slug);
                    std::fs::create_dir_all(&dir)?;
                    std::fs::write(dir.join("country-ips.json"), contents)?;
                    if let Some(edit) = self.editing.as_mut().filter(|p| p.slug == picker.slug) {
                        edit.country_ips_file = Some("country-ips.json".into());
                    } else if let Some(profile) =
                        self.profiles.iter_mut().find(|p| p.slug == picker.slug)
                    {
                        profile.country_ips_file = Some("country-ips.json".into());
                        ProfileStore::save(&self.profiles)?;
                    }
                    Ok(())
                })();
                match result {
                    Ok(()) => self.flash("Country IP database imported", ACCENT),
                    Err(error) => self.flash(format!("IP database import failed: {error}"), DANGER),
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
                rfd::FileDialog::new().pick_file().and_then(|p| {
                    std::fs::read_to_string(&p)
                        .ok()
                        .map(|c| (p.display().to_string(), c))
                })
            };
            let _ = tx.send(result);
        });
        self.picker = Some(Picker {
            purpose,
            slug,
            receiver: rx,
        });
    }

    // ---- egui ----------------------------------------------------------------

    fn nav_item(&mut self, ui: &mut egui::Ui, view: View, label: &str, icon: Icon) {
        if design::nav(ui, label, icon, self.view == view).clicked() {
            self.view = view;
        }
    }

    fn render_shell(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("nav")
            .resizable(false)
            .exact_width(214.0)
            .frame(
                egui::Frame::NONE
                    .fill(Color32::from_rgb(16, 24, 36))
                    .inner_margin(18),
            )
            .show(ctx, |ui| {
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(36.0), Sense::hover());
                    design::icon(ui, rect, Icon::Shield, ACCENT);
                    ui.vertical(|ui| {
                        ui.label(RichText::new("RVPN").size(24.0).strong().color(TEXT));
                        ui.label(RichText::new("WINDOWS").size(10.0).color(MUTED));
                    });
                });
                ui.add_space(34.0);
                ui.label(RichText::new("WORKSPACE").size(10.0).color(MUTED));
                ui.add_space(8.0);
                self.nav_item(ui, View::Connect, "Connection", Icon::Power);
                self.nav_item(ui, View::Profiles, "Profiles", Icon::Servers);
                self.nav_item(ui, View::Routing, "Routing rules", Icon::Route);
                self.nav_item(ui, View::Settings, "Settings", Icon::Settings);
                self.nav_item(ui, View::Logs, "Activity", Icon::Activity);
                ui.with_layout(Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.label(
                        RichText::new(format!("VERSION {}", env!("CARGO_PKG_VERSION")))
                            .size(10.0)
                            .color(MUTED),
                    );
                    if ui
                        .add_sized(
                            [ui.available_width(), 34.0],
                            egui::Button::new("Disconnect & quit").frame(false),
                        )
                        .clicked()
                    {
                        self.request_quit();
                    }
                    if self.tray.is_some()
                        && ui
                            .add_sized(
                                [ui.available_width(), 34.0],
                                egui::Button::new("Hide to tray").frame(false),
                            )
                            .clicked()
                    {
                        self.show_window = false;
                    }
                    ui.separator();
                    ui.label(
                        RichText::new(if self.settings.close_to_tray {
                            "Close button: keep in tray"
                        } else {
                            "Close button: disconnect & exit"
                        })
                        .small()
                        .color(MUTED),
                    );
                    ui.add_space(8.0);
                });
            });
        egui::TopBottomPanel::top("workspace-header")
            .exact_height(68.0)
            .frame(
                egui::Frame::NONE
                    .fill(BG)
                    .inner_margin(egui::Margin::symmetric(30, 15)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Workspace").color(MUTED));
                    ui.label(RichText::new("/").color(BORDER));
                    ui.label(
                        RichText::new(match self.view {
                            View::Connect => "Connection",
                            View::Profiles => "Profiles",
                            View::Routing => "Routing rules",
                            View::Settings => "Settings",
                            View::Logs => "Activity",
                        })
                        .strong(),
                    );
                    ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                        let (status, color) = match self.snapshot.phase {
                            EnginePhase::Connected { .. } => ("CONNECTED", ACCENT),
                            EnginePhase::Failed { .. } => ("NEEDS ATTENTION", DANGER),
                            EnginePhase::Idle => ("OFFLINE", MUTED),
                            EnginePhase::Stopping => ("DISCONNECTING", WARN),
                            _ => ("CONNECTING", WARN),
                        };
                        design::pill(ui, status, color);
                    });
                });
            });
        if let Some((msg, at, color)) = &self.flash {
            if at.elapsed().as_secs() < 7 {
                egui::TopBottomPanel::bottom("flash")
                    .frame(egui::Frame::NONE.fill(SURFACE).inner_margin(12))
                    .show(ctx, |ui| {
                        ui.colored_label(*color, msg);
                    });
            }
        }
        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(BG)
                    .inner_margin(egui::Margin::symmetric(30, 16)),
            )
            .show(ctx, |ui| {
                ui.add_enabled_ui(!self.force_quit, |ui| {
                    if self.view == View::Routing {
                        self.view_routing(ui);
                    } else {
                        egui::ScrollArea::vertical()
                            .id_salt("page-scroll")
                            .auto_shrink([false, false])
                            .show(ui, |ui| match self.view {
                                View::Connect => self.view_connect(ui),
                                View::Profiles => self.view_profiles(ui),
                                View::Settings => self.view_settings(ui),
                                View::Logs => self.view_logs(ui),
                                View::Routing => {}
                            });
                    }
                });
            });
        if self.force_quit {
            egui::Window::new("Closing RVPN")
                .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Disconnecting and restoring Windows settings…");
                    });
                });
        }
    }
}

impl eframe::App for RvpnApp {
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.connect_cancel.store(true, Ordering::SeqCst);
        if let Some(worker) = self.connect_thread.take() {
            let _ = worker.join();
        }
        if let Some(handle) = self.engine_slot.lock().unwrap().take() {
            handle.stop_and_wait();
        }
        if let Some(handle) = self.engine.take() {
            handle.stop_and_wait();
        }
        crate::sysproxy::restore_system_proxy();
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Closing the window parks the app in the tray (like the macOS
        // menu-bar app); Quit comes from the tray menu.
        if ctx.input(|i| i.viewport().close_requested()) {
            if !self.force_quit && self.settings.close_to_tray && self.tray.is_some() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.show_window = false;
                crate::platform::hide_main_window();
            } else {
                self.request_quit();
                if !self.shutdown_complete() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                }
            }
        }
        self.pump_background(ctx);
        self.poll_picker();

        // One background release check per launch (release builds only).
        self.start_update_check();

        self.render_shell(ctx);

        self.show_tofu_dialog(ctx);
        self.show_profile_editor(ctx);

        // Keep the UI at ~2 fps when idle, full rate while connecting.
        let running =
            self.connect_thread.is_some() || self.engine.as_ref().is_some_and(|e| e.is_active());
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
    fn view_routing(&mut self, ui: &mut egui::Ui) {
        design::heading(
            ui,
            "Routing rules",
            "Decide what goes Direct, through Proxy, or gets blocked.",
        );
        egui::ComboBox::from_id_salt("routing-profile")
            .selected_text(
                self.selected()
                    .map(|p| p.name.as_str())
                    .unwrap_or("Select profile"),
            )
            .show_ui(ui, |ui| {
                for p in &self.profiles {
                    ui.selectable_value(&mut self.selected_profile, Some(p.slug.clone()), &p.name);
                }
            });
        let Some(profile) = self.selected().cloned() else {
            ui.label("Create a profile first.");
            return;
        };
        if self.routing_draft.as_ref().map(|d| &d.slug) != Some(&profile.slug) {
            self.routing_draft = Some(crate::routing_ui::RoutingDraft::new(&profile));
        }
        let draft = self.routing_draft.as_mut().unwrap();
        if draft.show(ui, &profile) {
            let mut updated = profile.clone();
            updated.routing = Some(draft.normalized());
            updated.block_ads = draft.block_ads;
            let result = crate::routing::Router::for_profile(&updated).and_then(|_| {
                let mut profiles = self.profiles.clone();
                if let Some(p) = profiles.iter_mut().find(|p| p.slug == updated.slug) {
                    *p = updated;
                }
                ProfileStore::save(&profiles)?;
                self.profiles = profiles;
                Ok(())
            });
            match result {
                Ok(()) => {
                    if let Some(draft) = self.routing_draft.as_mut() {
                        draft.mark_saved();
                    }
                    self.flash("Routing saved — reconnect to apply", ACCENT);
                }
                Err(e) => self.flash(format!("Routing not saved: {e:#}"), DANGER),
            }
        }
    }

    fn view_connect(&mut self, ui: &mut egui::Ui) {
        design::heading(
            ui,
            "Your connection",
            "Choose a profile and control how your traffic is routed.",
        );
        if !matches!(self.update, UpdateState::Idle | UpdateState::Checking) {
            self.update_card(ui);
            ui.add_space(10.0);
        }
        if self.selected().is_none() {
            design::card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                design::section(
                    ui,
                    "Welcome to RVPN",
                    "Add a connection profile to get started.",
                );
                if design::primary(ui, "Create a profile").clicked() {
                    self.new_profile();
                }
                if ui.button("Import a .rvpn profile").clicked() {
                    self.spawn_picker(PickerPurpose::ImportProfile, String::new(), None);
                }
            });
            return;
        }
        let connected = matches!(self.snapshot.phase, EnginePhase::Connected { .. });
        let busy =
            self.connect_thread.is_some() || matches!(self.snapshot.phase, EnginePhase::Stopping);
        let width = ui.available_width();
        let left = (width * 0.58).max(330.0);
        ui.horizontal_top(|ui| {
            ui.allocate_ui_with_layout(
                egui::vec2(left, 0.0),
                Layout::top_down(egui::Align::LEFT),
                |ui| {
                    design::card().show(ui, |ui| {
                        ui.set_width(left - 44.0);
                        ui.vertical_centered(|ui| {
                            ui.add_space(5.0);
                            design::pill(
                                ui,
                                if self.selected().unwrap().mode == ConnMode::Proxy {
                                    "SYSTEM PROXY"
                                } else {
                                    "FULL TUNNEL"
                                },
                                design::BLUE,
                            );
                            ui.add_space(20.0);
                            let (rect, response) = ui.allocate_exact_size(
                                Vec2::splat(132.0),
                                if busy { Sense::hover() } else { Sense::click() },
                            );
                            let color = if busy {
                                WARN
                            } else if connected {
                                ACCENT
                            } else {
                                MUTED
                            };
                            let painter = ui.painter();
                            painter.circle_stroke(
                                rect.center(),
                                64.0,
                                egui::Stroke::new(1.0_f32, BORDER),
                            );
                            painter.circle_filled(
                                rect.center(),
                                53.0,
                                color.gamma_multiply(if response.hovered() { 0.16 } else { 0.08 }),
                            );
                            painter.circle_stroke(
                                rect.center(),
                                53.0,
                                egui::Stroke::new(2.0_f32, color),
                            );
                            design::icon(ui, rect.shrink(37.0), Icon::Power, color);
                            response.clone().on_hover_text(if connected {
                                "Disconnect"
                            } else {
                                "Connect"
                            });
                            response.widget_info(|| {
                                egui::WidgetInfo::labeled(
                                    egui::WidgetType::Button,
                                    ui.is_enabled(),
                                    if connected { "Disconnect" } else { "Connect" },
                                )
                            });
                            if response.clicked() {
                                if connected {
                                    self.disconnect();
                                } else {
                                    self.start_connect();
                                }
                            }
                            ui.add_space(14.0);
                            let title = match self.snapshot.phase {
                                EnginePhase::Connected { .. } => "You're connected",
                                EnginePhase::Failed { .. } => "Let's try again",
                                EnginePhase::Starting | EnginePhase::Connecting { .. } => {
                                    "Getting connected"
                                }
                                EnginePhase::Stopping => "Disconnecting",
                                EnginePhase::Idle => "Ready when you are",
                            };
                            ui.label(RichText::new(title).size(26.0).strong().color(TEXT));
                            ui.label(
                                RichText::new(if connected {
                                    "Your connection is active."
                                } else {
                                    "Choose your profile and connect."
                                })
                                .color(MUTED),
                            );
                            ui.add_space(14.0);
                            let label = if busy {
                                "Please wait…"
                            } else if connected {
                                "Disconnect"
                            } else {
                                "Connect"
                            };
                            if ui
                                .add_enabled(
                                    !busy,
                                    egui::Button::new(
                                        RichText::new(label).strong().size(16.0).color(BG),
                                    )
                                    .fill(if connected { ACCENT } else { design::BLUE })
                                    .min_size(egui::vec2(206.0, 44.0)),
                                )
                                .clicked()
                            {
                                if connected {
                                    self.disconnect();
                                } else {
                                    self.start_connect();
                                }
                            }
                            if busy
                                && !matches!(self.snapshot.phase, EnginePhase::Stopping)
                                && ui.small_button("Cancel connection").clicked()
                            {
                                self.disconnect();
                            }
                            ui.add_space(9.0);
                            if let EnginePhase::Connecting { detail } = &self.snapshot.phase {
                                ui.label(RichText::new(detail).small().color(WARN));
                            } else {
                                ui.label(
                                    RichText::new(
                                        "Closing RVPN restores your Windows proxy settings.",
                                    )
                                    .size(11.0)
                                    .color(MUTED),
                                );
                            }
                            ui.add_space(5.0);
                        });
                    });
                },
            );
            ui.allocate_ui_with_layout(
                egui::vec2((width - left - 10.0).max(230.0), 0.0),
                Layout::top_down(egui::Align::LEFT),
                |ui| {
                    design::card().show(ui, |ui| {
                        ui.set_width((width - left - 54.0).max(186.0));
                        design::section(ui, "Connection profile", "Select where you connect.");
                        egui::ComboBox::from_id_salt("profile")
                            .width(ui.available_width() - 12.0)
                            .selected_text(&self.selected().unwrap().name)
                            .show_ui(ui, |ui| {
                                for p in &self.profiles {
                                    ui.selectable_value(
                                        &mut self.selected_profile,
                                        Some(p.slug.clone()),
                                        &p.name,
                                    );
                                }
                            });
                        let selected = self.selected().unwrap().clone();
                        let host = url::Url::parse(&selected.server_address)
                            .ok()
                            .and_then(|u| u.host_str().map(str::to_string))
                            .unwrap_or_else(|| "Server not configured".into());
                        ui.label(RichText::new(host).small().color(MUTED));
                        ui.add_space(8.0);
                        ui.separator();
                        ui.add_space(8.0);
                        ui.label(RichText::new("Connection mode").strong());
                        let mut updated = selected.clone();
                        ui.add_enabled_ui(!connected && !busy, |ui| {
                            ui.horizontal(|ui| {
                                ui.selectable_value(
                                    &mut updated.mode,
                                    ConnMode::Proxy,
                                    "System proxy",
                                );
                                ui.selectable_value(
                                    &mut updated.mode,
                                    ConnMode::Tun,
                                    "Full tunnel",
                                );
                            });
                        });
                        ui.label(
                            RichText::new(if updated.mode == ConnMode::Proxy {
                                "For browsers and apps using Windows proxy."
                            } else {
                                "Routes device traffic through the VPN."
                            })
                            .small()
                            .color(MUTED),
                        );
                        if updated != selected {
                            self.persist_profile(updated);
                        }
                        ui.add_space(10.0);
                        if ui
                            .add_sized(
                                [ui.available_width(), 34.0],
                                egui::Button::new("Edit connection"),
                            )
                            .clicked()
                        {
                            self.edit_profile(selected, 0);
                        }
                        ui.separator();
                        if ui
                            .add_sized(
                                [ui.available_width(), 32.0],
                                egui::Button::new("Routing & country rules").frame(false),
                            )
                            .clicked()
                        {
                            self.view = View::Routing;
                        }
                        if ui
                            .add_sized(
                                [ui.available_width(), 32.0],
                                egui::Button::new("DNS & connection settings").frame(false),
                            )
                            .clicked()
                        {
                            self.view = View::Settings;
                            self.settings_tab = 1;
                        }
                    });
                },
            );
        });
        ui.add_space(16.0);
        ui.columns(3, |cols| {
            for (column, (label, value)) in cols.iter_mut().zip([
                (
                    "SESSION TIME",
                    self.snapshot
                        .connected_for_secs
                        .map(format_duration)
                        .unwrap_or_else(|| "—".into()),
                ),
                ("DOWNLOADED", fmt_bytes(self.snapshot.rx_bytes)),
                ("UPLOADED", fmt_bytes(self.snapshot.tx_bytes)),
            ]) {
                design::card().inner_margin(18).show(column, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(label).size(10.0).color(MUTED));
                    ui.label(RichText::new(value).size(23.0).strong().color(TEXT));
                });
            }
        });
        ui.add_space(16.0);
        design::card().inner_margin(16).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(26.0), Sense::hover());
                design::icon(ui, rect, Icon::Route, ACCENT);
                ui.vertical(|ui| {
                    ui.label(RichText::new("Routing data").strong());
                    let (text, color) = self
                        .geodata_status
                        .as_ref()
                        .map(|(s, w)| (s.as_str(), if *w { WARN } else { MUTED }))
                        .unwrap_or((
                            "GeoIP & GeoSite are checked automatically before Set Proxy.",
                            MUTED,
                        ));
                    ui.label(RichText::new(text).small().color(color));
                });
            });
        });
        if let EnginePhase::Failed { reason } = &self.snapshot.phase {
            ui.add_space(10.0);
            ui.colored_label(DANGER, reason);
            if ui.button("Open activity log").clicked() {
                self.view = View::Logs;
            }
        }
        if connected {
            egui::CollapsingHeader::new("Connection details").show(ui, |ui| {
                if let EnginePhase::Connected {
                    ip,
                    gateway,
                    server,
                } = &self.snapshot.phase
                {
                    grid_row(ui, "Local address", ip);
                    grid_row(ui, "Gateway", gateway);
                    grid_row(ui, "Server", server);
                }
            });
        }
    }

    fn new_profile(&mut self) {
        if self.profiles.len() >= MAX_PROFILES {
            self.flash("Profile limit reached", WARN);
            return;
        }
        let mut profile = Profile::new("New profile");
        profile.slug = format!(
            "profile-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        profile.ensure_unique_slug(&self.profiles);
        profile.mode = ConnMode::Proxy;
        self.edit_profile(profile, 0);
    }

    fn persist_profile(&mut self, updated: Profile) {
        let mut profiles = self.profiles.clone();
        if let Some(p) = profiles.iter_mut().find(|p| p.slug == updated.slug) {
            *p = updated;
        }
        match ProfileStore::save(&profiles) {
            Ok(()) => self.profiles = profiles,
            Err(error) => self.flash(format!("Could not save settings: {error}"), DANGER),
        }
    }

    fn view_profiles(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new("Your profiles").size(30.0).strong());
                ui.label(RichText::new("A home for every connection.").color(MUTED));
            });
            ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                if design::primary(ui, "+ New profile").clicked() {
                    self.new_profile();
                }
                if ui.button("Import .rvpn").clicked() {
                    self.spawn_picker(PickerPurpose::ImportProfile, String::new(), None);
                }
            });
        });
        ui.add_space(20.0);
        if self.profiles.is_empty() {
            design::card().show(ui, |ui| {
                design::section(
                    ui,
                    "Your first connection starts here",
                    "Create a profile or import a .rvpn file from your server.",
                );
            });
            return;
        }
        ui.label(
            RichText::new(format!(
                "{} / {} profiles",
                self.profiles.len(),
                MAX_PROFILES
            ))
            .small()
            .color(MUTED),
        );
        ui.add_space(6.0);
        for p in self.profiles.clone() {
            let selected = self.selected_profile.as_deref() == Some(p.slug.as_str());
            design::card()
                .stroke(egui::Stroke::new(
                    1.0_f32,
                    if selected {
                        ACCENT.gamma_multiply(0.5)
                    } else {
                        BORDER
                    },
                ))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        let (rect, _) = ui.allocate_exact_size(Vec2::splat(38.0), Sense::hover());
                        design::icon(
                            ui,
                            rect,
                            Icon::Servers,
                            if selected { ACCENT } else { MUTED },
                        );
                        ui.vertical(|ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(&p.name).size(18.0).strong());
                                if p.is_default {
                                    design::pill(ui, "DEFAULT", design::BLUE);
                                }
                            });
                            let host = url::Url::parse(&p.server_address)
                                .ok()
                                .and_then(|url| url.host_str().map(str::to_string))
                                .unwrap_or_else(|| "Server not configured".into());
                            ui.label(RichText::new(host).small().color(MUTED))
                                .on_hover_text(&p.server_address);
                        });
                        ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Edit profile").clicked() {
                                self.edit_profile(p.clone(), 0);
                            }
                            if selected {
                                design::pill(ui, "SELECTED", ACCENT);
                            }
                        });
                    });
                    ui.add_space(9.0);
                    ui.separator();
                    ui.add_space(5.0);
                    ui.horizontal_wrapped(|ui| {
                        design::pill(
                            ui,
                            if p.mode == ConnMode::Proxy {
                                "SYSTEM PROXY"
                            } else {
                                "FULL TUNNEL"
                            },
                            MUTED,
                        );
                        badge(ui, p.has_identity(), "Identity");
                        badge(ui, p.has_prekey(), "Server bundle");
                        ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.menu_button("More", |ui| {
                                if ui.button("Export profile").clicked() {
                                    match p.export(false) {
                                        Ok(doc) => {
                                            self.spawn_picker(
                                                PickerPurpose::ExportProfile,
                                                String::new(),
                                                Some(format!("{}.rvpn", p.slug)),
                                            );
                                            self.export_payload = Some(doc);
                                        }
                                        Err(error) => {
                                            self.flash(format!("Export failed: {error}"), DANGER)
                                        }
                                    }
                                    ui.close_menu();
                                }
                                if ui.button("Share for mobile…").clicked() {
                                    self.share_for_mobile(&p);
                                    ui.close_menu();
                                }
                                if ui
                                    .button(RichText::new("Delete profile").color(DANGER))
                                    .clicked()
                                {
                                    self.confirm_delete = Some(p.slug.clone());
                                    ui.close_menu();
                                }
                            });
                            let busy = self.connect_thread.is_some()
                                || self.engine.as_ref().is_some_and(|e| e.is_active());
                            if !selected
                                && ui
                                    .add_enabled(!busy, egui::Button::new("Use profile"))
                                    .clicked()
                            {
                                self.selected_profile = Some(p.slug.clone());
                                self.view = View::Connect;
                            }
                        });
                    });
                });
            ui.add_space(12.0);
        }
        if let Some(slug) = self.confirm_delete.clone() {
            egui::Window::new("Delete profile?")
                .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
                .resizable(false)
                .collapsible(false)
                .show(ui.ctx(), |ui| {
                    ui.label("This removes the profile and its identity key from this computer.");
                    ui.horizontal(|ui| {
                        if ui
                            .button(RichText::new("Delete profile").color(DANGER))
                            .clicked()
                        {
                            let result = self
                                .profiles
                                .iter()
                                .find(|p| p.slug == slug)
                                .map(ProfileStore::delete)
                                .transpose();
                            match result {
                                Ok(_) => {
                                    self.profiles.retain(|p| p.slug != slug);
                                    if self.selected_profile.as_deref() == Some(slug.as_str()) {
                                        self.selected_profile =
                                            self.profiles.first().map(|p| p.slug.clone());
                                    }
                                    if let Err(error) = ProfileStore::save(&self.profiles) {
                                        self.flash(
                                            format!("Could not save profiles: {error}"),
                                            DANGER,
                                        );
                                    }
                                    self.confirm_delete = None;
                                }
                                Err(error) => {
                                    self.flash(format!("Could not delete profile: {error}"), DANGER)
                                }
                            }
                        }
                        if ui.button("Cancel").clicked() {
                            self.confirm_delete = None;
                        }
                    });
                });
        }
    }

    fn view_settings(&mut self, ui: &mut egui::Ui) {
        design::heading(ui, "Settings", "Set up RVPN around the way you work.");
        ui.horizontal(|ui| {
            for (index, label) in ["General", "Connection & DNS", "Routing data"]
                .iter()
                .enumerate()
            {
                ui.selectable_value(&mut self.settings_tab, index, *label);
            }
        });
        ui.add_space(18.0);
        if self.settings_tab == 0 {
            self.update_card(ui);
        }
        if self.settings_tab == 0 {
            let mut changed = false;
            design::card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                design::section(ui, "Startup", "Choose what happens when RVPN starts.");
                changed |= design::toggle(
                    ui,
                    &mut self.settings.auto_connect,
                    "Connect automatically",
                    "Use your default profile when the app starts.",
                );
                ui.separator();
                changed |= design::toggle(
                    ui,
                    &mut self.settings.start_minimized,
                    "Start in the tray",
                    "Open quietly in the Windows notification area.",
                );
                ui.separator();
                if design::toggle(
                    ui,
                    &mut self.settings.launch_at_startup,
                    "Launch with Windows",
                    "Start RVPN when you sign in.",
                ) {
                    match platform::set_launch_at_startup(self.settings.launch_at_startup) {
                        Ok(()) => changed = true,
                        Err(error) => {
                            self.settings.launch_at_startup = !self.settings.launch_at_startup;
                            self.flash(format!("Startup registration failed: {error}"), DANGER);
                        }
                    }
                }
            });
            ui.add_space(16.0);
            design::card().show(ui,|ui| {
                ui.set_width(ui.available_width());
                design::section(ui,"Window & exit","Closing the app disconnects by default.");
                ui.add_enabled_ui(self.tray.is_some(),|ui| {
                    changed|=design::toggle(ui,&mut self.settings.close_to_tray,"Keep running when the window closes","The × button hides the app. Use Disconnect & quit to exit.");
                });
                ui.add_space(4.0);
                design::pill(ui,if self.settings.close_to_tray {"TRAY MODE ENABLED"} else {"CLOSE = DISCONNECT & EXIT"},ACCENT);
                ui.label(RichText::new("RVPN restores Windows proxy settings on exit and attempts recovery after an unexpected shutdown.").small().color(MUTED));
            });
            if changed {
                self.save_settings();
            }
        } else if self.settings_tab == 1 {
            design::card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                design::section(
                    ui,
                    "Profile settings",
                    "DNS and connection options are saved per profile.",
                );
                self.profile_selector(ui, "settings-profile");
                if let Some(profile) = self.selected().cloned() {
                    ui.add_space(12.0);
                    grid_row(
                        ui,
                        "Mode",
                        if profile.mode == ConnMode::Proxy {
                            "System proxy"
                        } else {
                            "Full tunnel (TUN)"
                        },
                    );
                    grid_row(ui, "Local proxy port", &profile.proxy_port.to_string());
                    grid_row(ui, "Tunnel DNS", &profile.dns_servers.join(", "));
                    grid_row(ui, "Direct DNS", &profile.bypass_dns_servers.join(", "));
                    grid_row(
                        ui,
                        "Ad & tracker blocking",
                        if profile.block_ads {
                            "Enabled"
                        } else {
                            "Disabled"
                        },
                    );
                    ui.add_space(14.0);
                    if design::primary(ui, "Edit connection & DNS").clicked() {
                        self.edit_profile(profile, 1);
                    }
                } else {
                    ui.label("Create a profile to configure a connection.");
                }
            });
            ui.add_space(16.0);
            design::card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                design::section(
                    ui,
                    "Traffic routing",
                    "Choose Direct, Proxy or Block for domains, IPs and countries.",
                );
                ui.label(
                    RichText::new(
                        "Rules are evaluated in order. Changes apply when you reconnect.",
                    )
                    .color(MUTED),
                );
                if ui.button("Open routing rules").clicked() {
                    self.view = View::Routing;
                }
            });
        } else {
            design::card().show(ui,|ui| {
                ui.set_width(ui.available_width());
                design::section(ui,"GeoIP & GeoSite","Automatically checked before each System Proxy connection.");
                design::pill(ui,"AUTOMATIC UPDATES",ACCENT);
                ui.label("Source: Loyalsoldier / v2ray-rules-dat");
                if let Some((status,warning))=&self.geodata_status {ui.colored_label(if *warning{WARN}else{ACCENT},status);}
                ui.label(RichText::new("Only changed data is downloaded through the internal tunnel. Both databases must pass verification before use. When an update is unavailable, RVPN keeps verified saved data or its embedded fallback.").color(MUTED));
                ui.add_space(10.0);
                grid_row(ui,"Storage","Local app data / rvpn-windows / geodata");
                ui.label(RichText::new("No file import is needed for Iran in System Proxy mode.").small().color(MUTED));
                if ui.button("Choose countries & rules").clicked(){self.view=View::Routing;}
            });
        }
    }

    fn profile_selector(&mut self, ui: &mut egui::Ui, id: &str) {
        egui::ComboBox::from_id_salt(id)
            .width(280.0)
            .selected_text(
                self.selected()
                    .map(|p| p.name.as_str())
                    .unwrap_or("Select profile"),
            )
            .show_ui(ui, |ui| {
                for p in &self.profiles {
                    ui.selectable_value(&mut self.selected_profile, Some(p.slug.clone()), &p.name);
                }
            });
    }

    fn edit_profile(&mut self, profile: Profile, tab: usize) {
        self.editing = Some(profile);
        self.editor_tab = tab;
        self.editor_buffers.clear();
    }

    fn view_logs(&mut self, ui: &mut egui::Ui) {
        design::heading(
            ui,
            "Activity",
            "Connection events and diagnostics, in one place.",
        );
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.log_filter)
                    .hint_text("Filter events…")
                    .desired_width(280.0),
            );
            if ui.button("Clear view").clicked() {
                self.engine_log.clear();
            }
        });
        ui.add_space(12.0);
        design::card().inner_margin(16).show(ui, |ui| {
            ui.set_width(ui.available_width());
            egui::ScrollArea::vertical()
                .id_salt("activity-log")
                .max_height((ui.available_height() - 24.0).max(250.0))
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for entry in self.engine_log.tail(500) {
                        let text = entry.formatted();
                        if !self.log_filter.is_empty()
                            && !text
                                .to_lowercase()
                                .contains(&self.log_filter.to_lowercase())
                        {
                            continue;
                        }
                        let color = match entry.level {
                            tracing::Level::ERROR => DANGER,
                            tracing::Level::WARN => WARN,
                            tracing::Level::INFO => TEXT,
                            _ => MUTED,
                        };
                        ui.label(RichText::new(text).monospace().size(12.0).color(color));
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
        let Some(mut editing) = self.editing.take() else {
            return;
        };
        let mut open = true;
        let mut keep = true;
        let existing = self.profiles.iter().any(|p| p.slug == editing.slug);
        egui::Window::new(if existing {"Edit connection profile"} else {"Create a connection profile"})
            .id(egui::Id::new("profile-editor")).anchor(Align2::CENTER_CENTER,Vec2::ZERO)
            .resizable(false).collapsible(false).open(&mut open).show(ctx,|ui| {
                ui.set_width(620.0);
                ui.horizontal(|ui| {
                    for (index,label) in ["Connection","DNS & routing","Identity & trust"].iter().enumerate() {
                        ui.selectable_value(&mut self.editor_tab,index,*label);
                    }
                });
                ui.add_space(12.0);
                egui::ScrollArea::vertical().id_salt("profile-editor-body").max_height((ctx.screen_rect().height()-240.0).max(300.0)).show(ui,|ui| {
                    ui.set_width(600.0);
                    match self.editor_tab {
                        0=>{
                            design::section(ui,"Connection","Give this profile a name and a server address.");
                            field(ui,"Profile name",&mut editing.name,"My connection");
                            field(ui,"Server address",&mut editing.server_address,"wss://your-server.com:443/api/v1/ws/tun");
                            ui.label(RichText::new("Connection mode").strong());
                            ui.horizontal(|ui| {ui.selectable_value(&mut editing.mode,ConnMode::Proxy,"System proxy");ui.selectable_value(&mut editing.mode,ConnMode::Tun,"Full tunnel (TUN)");});
                            ui.label(RichText::new(if editing.mode==ConnMode::Proxy {"Browsers and apps follow Windows proxy settings. Domain and country rules are available in Routing rules."} else {"Device traffic uses a Wintun adapter. Administrator access is required."}).small().color(MUTED));
                            if editing.mode==ConnMode::Proxy {
                                ui.horizontal(|ui| {ui.label("Local proxy port");ui.add(egui::DragValue::new(&mut editing.proxy_port).range(1024..=65535));});
                            } else {
                                ui.horizontal(|ui| {ui.label("Tunnel MTU");ui.add(egui::DragValue::new(&mut editing.mtu).range(1200..=1500));});
                            }
                            ui.add_space(14.0);
                            design::toggle(ui,&mut editing.is_default,"Use as default profile","Used for automatic connection at startup.");
                        },
                        1=>{
                            design::section(ui,"DNS resolvers","Changes take effect the next time you connect.");
                            list_field(ui,&mut self.editor_buffers,"tunnel-dns","Tunnel DNS",&mut editing.dns_servers,"1.1.1.1, 8.8.8.8",false);
                            ui.label(RichText::new("Used through the encrypted tunnel for destination IP and country lookup. IP addresses or IP:port, separated by commas.").small().color(MUTED));
                            if editing.mode==ConnMode::Proxy {
                                list_field(ui,&mut self.editor_buffers,"direct-dns","Direct DNS",&mut editing.bypass_dns_servers,"178.22.122.100, 185.51.200.2",false);
                                ui.label(RichText::new("Used only for domains explicitly routed Direct.").small().color(MUTED));
                            }
                            ui.add_space(12.0);
                            design::toggle(ui,&mut editing.block_ads,"Block ads & trackers",if editing.mode==ConnMode::Proxy {"Block domains using GeoSite rules."} else {"Enable the tunnel's DNS ad filtering."});
                            ui.separator();
                            if editing.mode==ConnMode::Proxy {
                                design::section(ui,"Domain & country rules","After saving, use Routing rules to set Direct / Proxy / Block and priority.");
                                ui.label(RichText::new("Iran GeoIP data is included and updates automatically.").color(MUTED));
                            } else {
                                design::toggle(ui,&mut editing.split_tunnel_enabled,"Split tunnel","Send selected destinations through your normal connection.");
                                ui.add_enabled_ui(editing.split_tunnel_enabled,|ui| {
                                    ui.label("Direct countries");
                                    ui.horizontal_wrapped(|ui| {
                                        for code in ["IR"].iter().chain(rvpn_mobile::rvpn_split_tunnel::supported_countries().iter()) {
                                            let on=editing.builtin_bypass_countries.iter().any(|c|c==code);
                                            if ui.selectable_label(on,*code).clicked(){if on{editing.builtin_bypass_countries.retain(|c|c!=code);}else{editing.builtin_bypass_countries.push(code.to_string());}}
                                        }
                                    });
                                    if editing.builtin_bypass_countries.iter().any(|c|c=="IR")&&editing.country_ips_file.is_none(){
                                        ui.colored_label(WARN,"TUN mode needs a custom IP database for Iran. System Proxy mode has Iran built in.");
                                    }
                                    list_field(ui,&mut self.editor_buffers,"bypass-networks","Direct IPs / CIDRs",&mut editing.bypass_networks,"192.168.0.0/16, 10.0.0.0/8",false);
                                    list_field(ui,&mut self.editor_buffers,"bypass-domains","Direct domains",&mut editing.bypass_domains,"example.ir",true);
                                    list_field(ui,&mut self.editor_buffers,"tunnel-domains","Always tunnel these domains",&mut editing.tunnel_domains,"example.com",true);
                                    ui.horizontal(|ui| {
                                        if ui.button("Import country IP database").clicked(){self.spawn_picker(PickerPurpose::ImportIpDb,editing.slug.clone(),None);}
                                        if editing.country_ips_file.is_some(){ui.colored_label(ACCENT,"Custom database loaded");}
                                    });
                                });
                            }
                        },
                        _=>{
                            design::section(ui,"Identity","Keep your identity key on this computer.");
                            badge(ui,editing.has_identity(),"Identity key available");
                            ui.horizontal(|ui| {
                                if !editing.has_identity()&&ui.button("Generate identity").clicked(){
                                    let result=std::fs::create_dir_all(editing.dir()).map_err(anyhow::Error::from)
                                        .and_then(|_|crate::identity::generate_identity(&editing.identity_path()));
                                    match result{Ok(())=>self.flash("Identity generated",ACCENT),Err(error)=>self.flash(format!("{error:#}"),DANGER)}
                                }
                                if !editing.has_identity()&&ui.button("Import identity").clicked(){self.spawn_picker(PickerPurpose::ImportIdentity,editing.slug.clone(),None);}
                            });
                            ui.add_space(12.0);ui.separator();ui.add_space(8.0);
                            design::section(ui,"Server bundle","Import the prekey bundle supplied by your server.");
                            badge(ui,editing.has_prekey(),"Server bundle available");
                            if ui.button("Import server bundle").clicked(){self.spawn_picker(PickerPurpose::ImportPrekey,editing.slug.clone(),None);}
                            ui.add_space(12.0);ui.separator();ui.add_space(8.0);
                            design::section(ui,"Server trust","The server identity is pinned after the first successful connection.");
                            if let Some(pin)=&editing.server_identity_pin {
                                ui.label(RichText::new(pin).monospace().small());
                                if ui.button("Reset saved server pin").clicked(){editing.server_identity_pin=None;}
                            }else{ui.label(RichText::new("The next connection will capture the server's identity.").color(MUTED));}
                        }
                    }
                });
                ui.add_space(12.0);ui.separator();
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Reconnect to apply connection changes.").small().color(MUTED));
                    ui.with_layout(Layout::right_to_left(egui::Align::Center),|ui| {
                        if design::primary(ui,"Save profile").clicked(){
                            match self.store_profile(&editing){
                                Ok(())=>{keep=false;self.flash("Profile saved",ACCENT);},
                                Err(error)=>self.flash(format!("Could not save: {error:#}"),DANGER),
                            }
                        }
                        if ui.button("Cancel").clicked(){keep=false;}
                    });
                });
            });
        if open && keep {
            self.editing = Some(editing);
        } else {
            self.editor_buffers.clear();
        }
    }

    fn store_profile(&mut self, editing: &Profile) -> anyhow::Result<()> {
        anyhow::ensure!(!editing.name.trim().is_empty(), "Enter a profile name");
        if !editing.server_address.trim().is_empty() {
            let url = url::Url::parse(editing.server_address.trim())?;
            anyhow::ensure!(
                matches!(url.scheme(), "ws" | "wss") && url.host_str().is_some(),
                "Enter a valid ws:// or wss:// server address"
            );
        }
        for dns in editing
            .dns_servers
            .iter()
            .chain(&editing.bypass_dns_servers)
        {
            let valid = dns
                .parse::<std::net::SocketAddr>()
                .map(|a| a.port() != 0)
                .or_else(|_| dns.parse::<std::net::IpAddr>().map(|_| true))
                .unwrap_or(false);
            anyhow::ensure!(valid, "Invalid DNS resolver: {dns}");
        }
        let mut profiles = self.profiles.clone();
        if let Some(profile) = profiles.iter_mut().find(|p| p.slug == editing.slug) {
            *profile = editing.clone();
        } else {
            anyhow::ensure!(profiles.len() < MAX_PROFILES, "Profile limit reached");
            profiles.push(editing.clone());
        }
        if editing.is_default {
            for profile in &mut profiles {
                profile.is_default = profile.slug == editing.slug;
            }
        }
        ProfileStore::save(&profiles)?;
        self.profiles = profiles;
        self.selected_profile = Some(editing.slug.clone());
        Ok(())
    }
}

// ============================================================================
// Small widgets
// ============================================================================

fn grid_row(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.set_width(ui.available_width());
        ui.label(RichText::new(key).small().color(Color32::from_gray(120)));
        ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                RichText::new(value)
                    .monospace()
                    .small()
                    .color(Color32::from_gray(210)),
            );
        });
    });
}

fn badge(ui: &mut egui::Ui, ok: bool, label: &str) {
    let (mark, color) = if ok {
        ("✓", ACCENT)
    } else {
        ("○", Color32::from_gray(110))
    };
    ui.label(
        RichText::new(format!("{mark} {label}"))
            .small()
            .color(color),
    );
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

fn field(ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str) {
    ui.label(RichText::new(label).strong());
    ui.add(
        egui::TextEdit::singleline(value)
            .min_size(egui::vec2(0.0, 36.0))
            .margin(egui::Margin::symmetric(10, 8))
            .hint_text(hint)
            .desired_width(f32::INFINITY),
    );
}
fn list_field(
    ui: &mut egui::Ui,
    buffers: &mut std::collections::BTreeMap<String, String>,
    id: &str,
    label: &str,
    values: &mut Vec<String>,
    hint: &str,
    multiline: bool,
) {
    ui.label(RichText::new(label).strong());
    let text = buffers
        .entry(id.into())
        .or_insert_with(|| values.join(if multiline { "\n" } else { ", " }));
    let edit = if multiline {
        egui::TextEdit::multiline(text).desired_rows(3)
    } else {
        egui::TextEdit::singleline(text)
    };
    if ui
        .add(edit.hint_text(hint).desired_width(f32::INFINITY))
        .changed()
    {
        *values = text
            .split(if multiline { '\n' } else { ',' })
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui::{
        epaint::{Primitive, Shape},
        Pos2, Rect,
    };
    use serde_json::json;

    fn fixture() -> RvpnApp {
        let (_tx, rx) = mpsc::channel();
        let mut profile = Profile::new("design-preview-isolated-profile");
        profile.name = "Everyday connection".into();
        profile.mode = ConnMode::Proxy;
        profile.server_address = "wss://nl.example.com:443/api/v1/ws/tun".into();
        profile.routing = Some(crate::routing::RoutingConfig::iran_direct());
        RvpnApp {
            view: View::Connect,
            profiles: vec![profile.clone()],
            settings: AppSettings::default(),
            engine: None,
            engine_events: rx,
            engine_slot: Arc::new(Mutex::new(None)),
            connect_thread: None,
            connect_cancel: Arc::new(AtomicBool::new(false)),
            geodata_status: Some(("202611142203 · checked; up to date".into(), false)),
            snapshot: EngineSnapshot {
                phase: EnginePhase::Idle,
                rx_bytes: 0,
                tx_bytes: 0,
                connected_for_secs: None,
                server_pin: None,
            },
            selected_profile: Some(profile.slug),
            routing_draft: None,
            engine_log: LogRing::default(),
            tray: None,
            picker: None,
            editing: None,
            confirm_delete: None,
            export_payload: None,
            tofu_dialog: None,
            flash: None,
            force_quit: false,
            show_window: true,
            editor_tab: 0,
            update: Default::default(),
            update_rx: None,
            update_relaunched: false,
            auto_update_silent: true,
            settings_tab: 0,
            log_filter: String::new(),
            editor_buffers: Default::default(),
        }
    }
    fn render(
        app: &mut RvpnApp,
        ctx: &egui::Context,
        size: [f32; 2],
        events: Vec<egui::Event>,
    ) -> egui::FullOutput {
        ctx.run(
            egui::RawInput {
                time: Some(ctx.input(|input| input.time) + 0.1),
                screen_rect: Some(Rect::from_min_size(
                    Pos2::ZERO,
                    egui::vec2(size[0], size[1]),
                )),
                events,
                ..Default::default()
            },
            |ctx| {
                app.render_shell(ctx);
                app.show_profile_editor(ctx);
            },
        )
    }
    fn texts(shape: &Shape, labels: &mut Vec<(String, Rect)>) {
        match shape {
            Shape::Text(text) => labels.push((
                text.galley.text().into(),
                text.galley.rect.translate(text.pos.to_vec2()),
            )),
            Shape::Vec(shapes) => {
                for shape in shapes {
                    texts(shape, labels);
                }
            }
            _ => {}
        }
    }
    fn labels(output: &egui::FullOutput) -> Vec<(String, Rect)> {
        let mut labels = vec![];
        for clipped in &output.shapes {
            texts(&clipped.shape, &mut labels);
        }
        labels
    }
    fn dump(ctx: &egui::Context, output: egui::FullOutput, size: [f32; 2], name: &str) {
        let Some(root) = std::env::var_os("RVPN_UI_PREVIEW_DIR") else {
            return;
        };
        let font = ctx.fonts(|f| f.image());
        let pixels: Vec<_> = font.srgba_pixels(None).flat_map(|p| p.to_array()).collect();
        let meshes:Vec<_>=ctx.tessellate(output.shapes,output.pixels_per_point).into_iter().filter_map(|clipped|{
            let Primitive::Mesh(mesh)=clipped.primitive else{return None;};
            Some(json!({"clip":[clipped.clip_rect.min.x,clipped.clip_rect.min.y,clipped.clip_rect.max.x,clipped.clip_rect.max.y],
                "vertices":mesh.vertices.iter().map(|v|json!([v.pos.x,v.pos.y,v.uv.x,v.uv.y,v.color.r(),v.color.g(),v.color.b(),v.color.a()])).collect::<Vec<_>>(),"indices":mesh.indices}))
        }).collect();
        let value = json!({"size":size,"atlas_size":font.size,"atlas_rgba":pixels,"meshes":meshes});
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            std::path::PathBuf::from(root).join(format!("{name}.json")),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn redesigned_views_and_editor_fit_and_export_real_egui_previews() {
        for (view, name) in [
            (View::Connect, "connection"),
            (View::Profiles, "profiles"),
            (View::Settings, "settings"),
            (View::Logs, "activity"),
            (View::Routing, "routing"),
        ] {
            let mut app = fixture();
            app.view = view;
            let ctx = egui::Context::default();
            design::apply(&ctx);
            let size = [1200.0, 860.0];
            let mut output = None;
            for _ in 0..4 {
                output = Some(render(&mut app, &ctx, size, vec![]));
            }
            let output = output.unwrap();
            let label_list = labels(&output);
            for (_, rect) in label_list.iter().filter(|(text, _)| {
                text == "Connect" || text == "Your connection" || text == "Disconnect & quit"
            }) {
                assert!(
                    rect.right() <= size[0] && rect.bottom() <= size[1],
                    "Clipped primary control on {name}: {rect:?}"
                );
            }
            if view == View::Connect {
                for expected in [
                    "Ready when you are",
                    "Connection profile",
                    "SESSION TIME",
                    "Routing data",
                ] {
                    assert!(
                        label_list.iter().any(|(text, _)| text.contains(expected)),
                        "Missing {expected}"
                    );
                }
            }
            dump(&ctx, output, size, name);
        }
        for tab in 0..3 {
            let mut app = fixture();
            app.edit_profile(app.profiles[0].clone(), tab);
            let ctx = egui::Context::default();
            design::apply(&ctx);
            let size = [1200.0, 860.0];
            let mut output = None;
            for _ in 0..4 {
                output = Some(render(&mut app, &ctx, size, vec![]));
            }
            let output = output.unwrap();
            assert!(labels(&output)
                .iter()
                .any(|(text, rect)| text == "Save profile" && rect.bottom() < size[1]));
            dump(&ctx, output, size, &format!("profile-editor-{tab}"));
        }
        let mut app = fixture();
        app.snapshot.phase = EnginePhase::Connected {
            ip: "http/socks5://127.0.0.1:1080".into(),
            gateway: "routing rules active".into(),
            server: app.profiles[0].server_address.clone(),
        };
        app.snapshot.connected_for_secs = Some(274);
        app.snapshot.rx_bytes = 34712325;
        app.snapshot.tx_bytes = 4239412;
        let ctx = egui::Context::default();
        design::apply(&ctx);
        let size = [1200.0, 860.0];
        let mut output = None;
        for _ in 0..4 {
            output = Some(render(&mut app, &ctx, size, vec![]));
        }
        dump(&ctx, output.unwrap(), size, "connection-active");
    }

    #[test]
    fn profile_form_keeps_typing_and_cancel_does_not_change_the_profile() {
        let mut app = fixture();
        let original = app.profiles[0].clone();
        app.edit_profile(original.clone(), 0);
        let ctx = egui::Context::default();
        design::apply(&ctx);
        let size = [1200.0, 860.0];
        let mut output = None;
        for _ in 0..4 {
            output = Some(render(&mut app, &ctx, size, vec![]));
        }
        // The rendered name identifies its actual TextEdit, not a test-only UI.
        let pos = labels(&output.unwrap())
            .into_iter()
            .find(|(text, rect)| text == &original.name && rect.left() < 500.0)
            .unwrap()
            .1
            .center();
        render(
            &mut app,
            &ctx,
            size,
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: Default::default(),
                },
            ],
        );
        render(
            &mut app,
            &ctx,
            size,
            vec![
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers: Default::default(),
                },
                egui::Event::Text(" edited".into()),
            ],
        );
        let edited = app.editing.as_ref().unwrap().name.clone();
        assert_ne!(edited, original.name);
        let output = render(&mut app, &ctx, size, vec![]);
        assert_eq!(
            app.editing.as_ref().unwrap().name,
            edited,
            "draft must survive the next frame"
        );
        assert_eq!(
            app.editing.as_ref().unwrap().slug,
            original.slug,
            "renaming must retain identity/bundle paths"
        );
        let pos = labels(&output)
            .into_iter()
            .find(|(text, _)| text == "Cancel")
            .unwrap()
            .1
            .center();
        render(
            &mut app,
            &ctx,
            size,
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: Default::default(),
                },
            ],
        );
        render(
            &mut app,
            &ctx,
            size,
            vec![egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: Default::default(),
            }],
        );
        assert!(app.editing.is_none());
        assert_eq!(app.profiles[0], original);
    }

    #[test]
    fn connection_primary_controls_fit_at_minimum_window_size() {
        let mut app = fixture();
        let ctx = egui::Context::default();
        design::apply(&ctx);
        let size = [1020.0, 740.0];
        let mut output = None;
        for _ in 0..4 {
            output = Some(render(&mut app, &ctx, size, vec![]));
        }
        let output = output.unwrap();
        let found = labels(&output)
            .into_iter()
            .find(|(text, _)| text == "Connect")
            .unwrap();
        assert!(found.1.right() < size[0] && found.1.bottom() < size[1]);
        dump(&ctx, output, size, "connection-compact");
    }

    #[test]
    fn routing_confirmation_stays_visible_at_minimum_window_size() {
        let mut app = fixture();
        app.view = View::Routing;
        let ctx = egui::Context::default();
        design::apply(&ctx);
        let size = [1020.0, 740.0];
        let mut output = None;
        for _ in 0..4 {
            output = Some(render(&mut app, &ctx, size, vec![]));
        }
        let output = output.unwrap();
        let confirm = labels(&output)
            .into_iter()
            .find(|(text, _)| text == "Confirm")
            .unwrap();
        assert!(
            confirm.1.bottom() < size[1],
            "Routing confirmation is clipped: {:?}",
            confirm.1
        );
        dump(&ctx, output, size, "routing-compact");
    }

    #[test]
    fn quit_cancels_pending_connection_and_waits_for_its_worker() {
        let mut app = fixture();
        let cancel = app.connect_cancel.clone();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let release = barrier.clone();
        app.connect_thread = Some(std::thread::spawn(move || {
            while !cancel.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
            release.wait();
        }));
        app.request_quit();
        assert!(app.force_quit && app.connect_cancel.load(Ordering::SeqCst));
        assert!(
            !app.shutdown_complete(),
            "the close must wait for a pending connect"
        );
        barrier.wait();
        app.connect_thread.take().unwrap().join().unwrap();
        assert!(app.shutdown_complete());
    }
}
