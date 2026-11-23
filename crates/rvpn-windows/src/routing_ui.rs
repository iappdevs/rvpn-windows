//! Routing controls arranged from v2rayN's Windows RoutingRuleSettingWindow
//! and RoutingRuleDetailsWindow: toolbar, settings form, rule grid, footer;
//! a separate details dialog with Domain / IP / Process columns.
use std::collections::BTreeSet;
use std::sync::mpsc::{self, Receiver};

use crate::profile::Profile;
use crate::routing::{DomainStrategy, Outbound, Router, RoutingConfig, Rule};
use eframe::egui::{
    self, Align, Color32, FontId, Layout, Rect, RichText, Sense, Stroke, StrokeKind, Vec2,
};

const BLUE: Color32 = crate::ui::ACCENT;
const LINE: Color32 = crate::ui::BORDER;
const PANEL: Color32 = crate::ui::SURFACE;
const MUTED: Color32 = crate::ui::MUTED;
const HEADERS: [&str; 4] = ["", "Rule name", "outboundTag", "Domain / IP"];

#[derive(Clone, Copy)]
enum Action {
    Add,
    Edit,
    Duplicate,
    Remove,
    SelectAll,
    Top,
    Up,
    Down,
    Bottom,
    Export,
}

pub struct RoutingDraft {
    pub slug: String,
    pub config: RoutingConfig,
    pub block_ads: bool,
    original: RoutingConfig,
    original_block_ads: bool,
    selection: BTreeSet<usize>,
    editor: Option<RuleEditor>,
    import_text: Option<String>,
    file_receiver: Option<Receiver<Result<String, String>>>,
    message: Option<String>,
    test_open: bool,
    test_host: String,
    test_ips: String,
    test_result: String,
    countries: Vec<String>,
    sites: Vec<String>,
    geo_generation: u64,
}

impl RoutingDraft {
    pub fn new(profile: &Profile) -> Self {
        let config = RoutingConfig::from_profile(profile);
        Self {
            slug: profile.slug.clone(),
            original: config.clone(),
            config,
            block_ads: profile.block_ads,
            original_block_ads: profile.block_ads,
            selection: BTreeSet::new(),
            editor: None,
            import_text: None,
            file_receiver: None,
            message: None,
            test_open: false,
            test_host: String::new(),
            test_ips: String::new(),
            test_result: String::new(),
            countries: crate::routing::country_codes(),
            sites: crate::routing::geosite_groups(),
            geo_generation: crate::geodata::generation(),
        }
    }

    pub fn normalized(&self) -> RoutingConfig {
        let mut config = self.config.clone();
        for rule in &mut config.rules {
            rule.domains = lines(&rule.domains.join("\n"));
            rule.ips = lines(&rule.ips.join("\n"));
        }
        config
    }

    pub fn mark_saved(&mut self) {
        self.config = self.normalized();
        self.original = self.config.clone();
        self.original_block_ads = self.block_ads;
    }

    fn cancel(&mut self) {
        self.config = self.original.clone();
        self.block_ads = self.original_block_ads;
        self.selection.clear();
        self.editor = None;
        self.message = None;
    }

    /// Returns true only when the panel's Confirm button is pressed.
    pub fn show(&mut self, ui: &mut egui::Ui, profile: &Profile) -> bool {
        let generation = crate::geodata::generation();
        if self.geo_generation != generation {
            self.countries = crate::routing::country_codes();
            self.sites = crate::routing::geosite_groups();
            self.geo_generation = generation;
        }
        if let Some(rx) = &self.file_receiver {
            if let Ok(result) = rx.try_recv() {
                self.file_receiver = None;
                match result {
                    Ok(text) => self.import_text = Some(text),
                    Err(error) => self.message = Some(error),
                }
            }
        }
        let mut confirm = false;
        ui.scope(|ui| {
            routing_style(ui);
            egui::Frame::NONE
                .fill(PANEL)
                .corner_radius(14).inner_margin(14.0)
                .show(ui, |ui| {
                    ui.set_min_size(ui.available_size());
                    let locked = self.editor.is_some() || self.import_text.is_some();
                    ui.add_enabled_ui(!locked, |ui| {
                        self.toolbar(ui);
                        ui.add_space(10.0);
                        self.settings_form(ui, profile);
                        ui.add_space(8.0);

                        let footer_height = if self.message.is_some() { 78.0 } else { 58.0 };
                        let table_height = (ui.available_height() - footer_height).max(120.0);
                        self.rule_table(ui, table_height);
                        ui.add_space(6.0);
                        if let Some(message) = &self.message {
                            ui.colored_label(Color32::from_rgb(240, 175, 80), message);
                        }
                        ui.horizontal(|ui| {
                            ui.small(format!(
                                "{} rules · first match wins · reconnect after Confirm",
                                self.config.rules.len()
                            ));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui
                                    .add_sized([100.0, 30.0], egui::Button::new("Cancel"))
                                    .clicked()
                                {
                                    self.cancel();
                                }
                                if ui
                                    .add_sized(
                                        [100.0, 30.0],
                                        egui::Button::new("Confirm").fill(BLUE),
                                    )
                                    .clicked()
                                {
                                    confirm = true;
                                }
                            });
                        });
                    });
                });
        });
        self.details_dialog(ui.ctx(), profile);
        self.import_dialog(ui.ctx(), profile);
        self.test_dialog(ui.ctx(), profile);
        confirm
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        let mut action = None;
        egui::Frame::NONE
            .fill(Color32::from_rgb(43, 43, 47))
            .inner_margin(6.0)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    if ui.button("+ Add Rule").clicked() {
                        action = Some(Action::Add);
                    }
                    ui.separator();
                    if ui
                        .add_enabled(
                            self.file_receiver.is_none(),
                            egui::Button::new("Import rules from file"),
                        )
                        .clicked()
                    {
                        let (tx, rx) = mpsc::channel();
                        self.file_receiver = Some(rx);
                        std::thread::spawn(move || {
                            let result = rfd::FileDialog::new()
                                .add_filter("Routing JSON", &["json"])
                                .pick_file()
                                .map(|p| std::fs::read_to_string(p).map_err(|e| e.to_string()));
                            let _ =
                                tx.send(result.unwrap_or_else(|| Err("Import cancelled".into())));
                        });
                    }
                    ui.separator();
                    if ui
                        .button("Import rules from clipboard")
                        .on_hover_text("Paste routing JSON into the import dialog")
                        .clicked()
                    {
                        self.import_text = Some(String::new());
                    }
                    ui.separator();
                    ui.add_enabled(false, egui::Button::new("Import rules from URL"))
                        .on_disabled_hover_text(
                            "URL subscriptions are not supported by RVPN. Use a local JSON file.",
                        );
                    ui.menu_button("More", |ui| {
                        if ui.button("Preset: Iran direct").clicked() {
                            self.config = RoutingConfig::iran_direct();
                            self.selection.clear();
                            ui.close_menu();
                        }
                        if ui.button("All proxy").clicked() {
                            self.config = RoutingConfig::default();
                            self.selection.clear();
                            ui.close_menu();
                        }
                        if ui.button("All direct").clicked() {
                            self.config = RoutingConfig {
                                default_outbound: Outbound::Direct,
                                ..RoutingConfig::default()
                            };
                            self.selection.clear();
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui.button("Test routing decision…").clicked() {
                            self.test_open = true;
                            ui.close_menu();
                        }
                    });
                });
            });
        if let Some(action) = action {
            self.action(action, ui.ctx());
        }
    }

    fn settings_form(&mut self, ui: &mut egui::Ui, profile: &Profile) {
        egui::Grid::new("routing-settings-form")
            .num_columns(2)
            .spacing([12.0, 10.0])
            .show(ui, |ui| {
                ui.label("Domain strategy");
                ui.horizontal_wrapped(|ui| {
                    egui::ComboBox::from_id_salt("routing-domain-strategy")
                        .width(200.0)
                        .selected_text(format!("{:?}", self.config.strategy))
                        .show_ui(ui, |ui| {
                            for value in [
                                DomainStrategy::AsIs,
                                DomainStrategy::IPIfNonMatch,
                                DomainStrategy::IPOnDemand,
                            ] {
                                ui.selectable_value(
                                    &mut self.config.strategy,
                                    value,
                                    format!("{value:?}"),
                                );
                            }
                        });
                    ui.label("Default outbound");
                    outbound_picker(
                        ui,
                        "default-outbound",
                        &mut self.config.default_outbound,
                        140.0,
                    );
                });
                ui.end_row();
            });
        ui.horizontal_wrapped(|ui| {
            ui.checkbox(&mut self.block_ads, "Block ads / trackers");
            ui.small(format!(
                "GeoIP: {} countries · GeoSite: {} groups · automatic updates",
                self.countries.len(),
                self.sites.len()
            ));
            if profile.mode == crate::profile::ConnMode::Tun {
                ui.colored_label(
                    Color32::GREEN,
                    "Full tunnel follows these rules: Direct GeoIP/CIDR rules bypass the tunnel",
                )
                .on_hover_text(
                    "Country and CIDR rules become OS bypass routes; domain rules apply to the \
                     DNS layer and fully in proxy mode. Block rules apply in proxy mode and to ads.",
                );
            }
        });
    }

    fn rule_table(&mut self, ui: &mut egui::Ui, height: f32) {
        let selected_count = self.selection.len();
        let mut action = None;
        ui.horizontal(|ui| {
            ui.selectable_label(true, RichText::new("Rule List").color(BLUE))
                .on_hover_text("Double-click a row to edit");
            if ui
                .add_enabled(selected_count == 1, egui::Button::new("Edit"))
                .clicked()
            {
                action = Some(Action::Edit);
            }
            for (label, command) in [
                ("Remove", Action::Remove),
                ("Top", Action::Top),
                ("Up", Action::Up),
                ("Down", Action::Down),
                ("Bottom", Action::Bottom),
            ] {
                if ui
                    .add_enabled(selected_count > 0, egui::Button::new(label))
                    .clicked()
                {
                    action = Some(command);
                }
            }
        });
        let widths=[54.0,190.0,120.0,(ui.available_width()-366.0).max(290.0)];
        let total: f32 = widths.iter().sum();
        let table = egui::Frame::NONE
            .stroke(Stroke::new(1.0_f32, LINE))
            .show(ui, |ui| {
                egui::ScrollArea::horizontal()
                    .id_salt("v2rayn-rule-grid")
                    .auto_shrink([false, false])
                    .max_height((height - 30.0).max(80.0))
                    .show(ui, |ui| {
                        ui.set_min_width(total);
                        ui.spacing_mut().item_spacing.y = 0.0;
                        let (header, _) =
                            ui.allocate_exact_size(Vec2::new(total, 30.0), Sense::hover());
                        ui.painter()
                            .rect_filled(header, 0, crate::ui::RAISED);
                        cells(
                            ui,
                            header,
                            &HEADERS.map(str::to_string),
                            &widths,
                            Color32::from_gray(225),
                        );
                        egui::ScrollArea::vertical()
                            .id_salt("routing-table-body")
                            .auto_shrink([false, false])
                            .max_height((height - 76.0).max(60.0))
                            .show(ui, |ui| {
                                for (index, rule) in self.config.rules.iter_mut().enumerate() {
                                    let (rect, response) = ui.allocate_exact_size(
                                        Vec2::new(total, 30.0),
                                        Sense::click(),
                                    );
                                    let chosen = self.selection.contains(&index);
                                    let fill = if chosen {
                                        Color32::from_rgb(31, 64, 66)
                                    } else if index % 2 == 0 {
                                        Color32::from_rgb(24, 34, 49)
                                    } else {
                                        PANEL
                                    };
                                    ui.painter().rect_filled(rect, 0, fill);
                                    let target = rule
                                        .domains
                                        .iter()
                                        .chain(rule.ips.iter())
                                        .cloned()
                                        .collect::<Vec<_>>()
                                        .join(", ");
                                    let text = [
                                        String::new(), rule.name.clone(),
                                        outbound_label(rule.outbound).into(), target,
                                    ];
                                    cells(
                                        ui,
                                        rect,
                                        &text,
                                        &widths,
                                        if rule.enabled {
                                            Color32::from_gray(222)
                                        } else {
                                            MUTED
                                        },
                                    );
                                    let check_rect = Rect::from_min_size(
                                        rect.min + egui::vec2(17.0, 5.0),
                                        egui::vec2(24.0, 20.0),
                                    );
                                    ui.put(
                                        check_rect,
                                        egui::Checkbox::without_text(&mut rule.enabled),
                                    );
                                    if response.clicked() {
                                        if !ui.input(|i| i.modifiers.command || i.modifiers.shift) {
                                            self.selection.clear();
                                        }
                                        if chosen && ui.input(|i| i.modifiers.command) {
                                            self.selection.remove(&index);
                                        } else {
                                            self.selection.insert(index);
                                        }
                                    }
                                    if response.double_clicked() {
                                        self.selection = BTreeSet::from([index]);
                                        action = Some(Action::Edit);
                                    }
                                    response.context_menu(|ui| {
                                        if !self.selection.contains(&index) {
                                            self.selection = BTreeSet::from([index]);
                                        }
                                        for (label, command) in [
                                            ("Add Rule", Action::Add),
                                            ("Edit", Action::Edit),
                                            ("Duplicate", Action::Duplicate),
                                            ("Remove", Action::Remove),
                                            ("Select All", Action::SelectAll),
                                            ("Export selected rules", Action::Export),
                                        ] {
                                            if ui.button(label).clicked() {
                                                action = Some(command);
                                                ui.close_menu();
                                            }
                                        }
                                        ui.separator();
                                        for (label, command) in [
                                            ("Move to top     T", Action::Top),
                                            ("Move up           U", Action::Up),
                                            ("Move down      D", Action::Down),
                                            ("Move to bottom B", Action::Bottom),
                                        ] {
                                            if ui.button(label).clicked() {
                                                action = Some(command);
                                                ui.close_menu();
                                            }
                                        }
                                    });
                                }
                                let blank_height =
                                    (height - 65.0 - 30.0 * self.config.rules.len() as f32)
                                        .max(30.0);
                                ui.allocate_space(Vec2::new(total, blank_height));
                            });
                    });
            });
        if table.response.contains_pointer() && !ui.ctx().wants_keyboard_input() {
            ui.input(|i| {
                if i.modifiers.command && i.key_pressed(egui::Key::A) {
                    action = Some(Action::SelectAll);
                }
                if i.key_pressed(egui::Key::Delete) || i.key_pressed(egui::Key::Backspace) {
                    action = Some(Action::Remove);
                }
                if i.key_pressed(egui::Key::Enter) {
                    action = Some(Action::Edit);
                }
                if i.key_pressed(egui::Key::T) {
                    action = Some(Action::Top);
                }
                if i.key_pressed(egui::Key::U) {
                    action = Some(Action::Up);
                }
                if i.key_pressed(egui::Key::D) {
                    action = Some(Action::Down);
                }
                if i.key_pressed(egui::Key::B) {
                    action = Some(Action::Bottom);
                }
            });
        }
        if let Some(action) = action {
            self.action(action, ui.ctx());
        }
    }

    fn action(&mut self, action: Action, ctx: &egui::Context) {
        let index = self.selection.first().copied();
        match action {
            Action::Add => self.editor = Some(RuleEditor::new(None, Rule::default())),
            Action::Edit => {
                if let Some(index) = index {
                    self.editor = Some(RuleEditor::new(
                        Some(index),
                        self.config.rules[index].clone(),
                    ));
                }
            }
            Action::Duplicate => {
                if let Some(index) = index {
                    let mut rule = self.config.rules[index].clone();
                    rule.name.push_str(" (copy)");
                    self.editor = Some(RuleEditor::new(None, rule));
                }
            }
            Action::SelectAll => self.selection = (0..self.config.rules.len()).collect(),
            Action::Remove => {
                let mut i = 0;
                self.config.rules.retain(|_| {
                    let keep = !self.selection.contains(&i);
                    i += 1;
                    keep
                });
                self.selection.clear();
            }
            Action::Export => {
                let rules: Vec<_> = self
                    .selection
                    .iter()
                    .filter_map(|i| self.config.rules.get(*i))
                    .cloned()
                    .collect();
                ctx.copy_text(serde_json::to_string_pretty(&rules).unwrap_or_default());
            }
            Action::Top | Action::Bottom => {
                let mut selected = vec![];
                let mut other = vec![];
                for (i, rule) in self.config.rules.drain(..).enumerate() {
                    if self.selection.contains(&i) {
                        selected.push(rule)
                    } else {
                        other.push(rule)
                    }
                }
                let count = selected.len();
                if matches!(action, Action::Top) {
                    selected.extend(other);
                    self.config.rules = selected;
                    self.selection = (0..count).collect();
                } else {
                    let offset = other.len();
                    other.extend(selected);
                    self.config.rules = other;
                    self.selection = (offset..offset + count).collect();
                }
            }
            Action::Up => {
                for i in self.selection.clone() {
                    if i > 0 && !self.selection.contains(&(i - 1)) {
                        self.config.rules.swap(i, i - 1);
                        self.selection.remove(&i);
                        self.selection.insert(i - 1);
                    }
                }
            }
            Action::Down => {
                for i in self.selection.clone().into_iter().rev() {
                    if i + 1 < self.config.rules.len() && !self.selection.contains(&(i + 1)) {
                        self.config.rules.swap(i, i + 1);
                        self.selection.remove(&i);
                        self.selection.insert(i + 1);
                    }
                }
            }
        }
    }

    fn details_dialog(&mut self, ctx: &egui::Context, profile: &Profile) {
        let Some(mut edit) = self.editor.take() else {
            return;
        };
        let mut open = true;
        let mut accepted = false;
        let mut cancelled = false;
        egui::Window::new("Routing Rule Details Setting")
            .id(egui::Id::new("routing-rule-details"))
            .default_size([900.0, 650.0])
            .min_size([720.0, 560.0])
            .resizable(true)
            .collapsible(false)
            .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
            .open(&mut open)
            .show(ctx, |ui| {
                routing_style(ui);
                egui::Grid::new("rule-detail-form")
                    .num_columns(3)
                    .spacing([12.0, 10.0])
                    .show(ui, |ui| {
                        ui.label("Remarks");
                        ui.add(
                            egui::TextEdit::singleline(&mut edit.rule.name).desired_width(200.0),
                        );
                        ui.checkbox(&mut edit.rule.enabled, "Enabled");
                        ui.end_row();
                        ui.label("Rule Type");
                        egui::ComboBox::from_id_salt("detail-type")
                            .width(200.0)
                            .selected_text("Routing")
                            .show_ui(ui, |ui| {
                                let _ = ui.selectable_label(true, "Routing");
                            });
                        ui.small("Domain and IP routing");
                        ui.end_row();
                        ui.label("outboundTag");
                        outbound_picker(ui, "detail-outbound", &mut edit.rule.outbound, 200.0);
                        ui.small("proxy / direct / block");
                        ui.end_row();
                        ui.label("port");
                        disabled_field(ui, "", 200.0);
                        ui.small("Port matching is not supported by RVPN");
                        ui.end_row();
                        ui.label("protocol");
                        ui.add_enabled_ui(false, |ui| {
                            ui.horizontal(|ui| {
                                for value in ["http", "tls", "bittorrent"] {
                                    let _ = ui.selectable_label(false, value);
                                }
                            });
                        });
                        ui.small("Protocol matching is not supported by RVPN");
                        ui.end_row();
                        ui.label("inboundTag");
                        ui.add_enabled_ui(false, |ui| {
                            ui.horizontal(|ui| {
                                let _ = ui.selectable_label(true, "http");
                                let _ = ui.selectable_label(true, "socks");
                            });
                        });
                        ui.small("Shared rules for the mixed inbound");
                        ui.end_row();
                        ui.label("network");
                        ui.add_enabled_ui(false, |ui| {
                            egui::ComboBox::from_id_salt("detail-network")
                                .width(200.0)
                                .selected_text("tcp")
                                .show_ui(ui, |ui| {
                                    ui.label("tcp");
                                });
                        });
                        ui.small("TCP proxy connections");
                        ui.end_row();
                    });
                ui.add_space(12.0);
                let columns_height = (ui.available_height() - 68.0).max(170.0);
                ui.columns(3, |columns| {
                    egui::Frame::group(columns[0].style())
                        .stroke(Stroke::new(1.0_f32, LINE))
                        .show(&mut columns[0], |ui| {
                            ui.label(RichText::new("Domain").strong());
                            geo_picker(
                                ui,
                                "geosite-picker",
                                "Add GeoSite…",
                                &self.sites,
                                &mut edit.site_search,
                                &mut edit.domains,
                                "geosite:",
                            );
                            textarea(
                                ui,
                                "domain-text",
                                &mut edit.domains,
                                columns_height - 55.0,
                                "domain:example.com\nfull:example.org\ngeosite:google",
                            );
                        });
                    egui::Frame::group(columns[1].style())
                        .stroke(Stroke::new(1.0_f32, LINE))
                        .show(&mut columns[1], |ui| {
                            ui.label(RichText::new("IP or IP CIDR").strong());
                            geo_picker(
                                ui,
                                "geoip-picker",
                                "Add country / GeoIP…",
                                &self.countries,
                                &mut edit.country_search,
                                &mut edit.ips,
                                "geoip:",
                            );
                            textarea(
                                ui,
                                "ip-text",
                                &mut edit.ips,
                                columns_height - 55.0,
                                "geoip:ir\ngeoip:private\n192.168.0.0/16",
                            );
                        });
                    egui::Frame::group(columns[2].style())
                        .stroke(Stroke::new(1.0_f32, LINE))
                        .show(&mut columns[2], |ui| {
                            ui.label(RichText::new("Process (Linux/Windows)").strong());
                            ui.add_space(27.0);
                            ui.add_enabled_ui(false, |ui| {
                                textarea(
                                    ui,
                                    "process-text",
                                    &mut edit.process,
                                    columns_height - 55.0,
                                    "Process routing is not supported by RVPN",
                                );
                            });
                        });
                });
                if let Some(error) = &edit.error {
                    ui.colored_label(Color32::from_rgb(240, 175, 80), error);
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.checkbox(&mut edit.auto_sort, "Auto sort domain / IP entries");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .add_sized([100.0, 30.0], egui::Button::new("Cancel"))
                            .clicked()
                        {
                            cancelled = true;
                        }
                        if ui
                            .add_sized([100.0, 30.0], egui::Button::new("Confirm").fill(BLUE))
                            .clicked()
                        {
                            accepted = true;
                        }
                    });
                });
            });
        if accepted && self.accept_editor(&mut edit, profile) {
            return;
        }
        if open && !cancelled {
            self.editor = Some(edit);
        }
    }

    fn accept_editor(&mut self, edit: &mut RuleEditor, profile: &Profile) -> bool {
        let mut candidate = self.normalized();
        let rule = edit.normalized();
        if let Some(index) = edit.index {
            candidate.rules[index] = rule;
        } else {
            candidate.rules.push(rule);
        }
        let mut profile = profile.clone();
        profile.routing = Some(candidate.clone());
        profile.block_ads = self.block_ads;
        match Router::for_profile(&profile) {
            Ok(_) => {
                let index = edit.index.unwrap_or(candidate.rules.len() - 1);
                self.config = candidate;
                self.selection = BTreeSet::from([index]);
                return true;
            }
            Err(error) => edit.error = Some(format!("{error:#}")),
        }
        false
    }

    fn import_dialog(&mut self, ctx: &egui::Context, profile: &Profile) {
        let Some(mut text) = self.import_text.take() else {
            return;
        };
        let mut open = true;
        let mut import = false;
        let mut cancel = false;
        egui::Window::new("Import routing rules")
            .id(egui::Id::new("routing-import"))
            .default_size([620.0, 380.0])
            .collapsible(false)
            .open(&mut open)
            .show(ctx, |ui| {
                routing_style(ui);
                ui.label("Paste RVPN routing JSON (a configuration or a rule array).");
                textarea(
                    ui,
                    "import-json",
                    &mut text,
                    270.0,
                    "Paste JSON here with Ctrl+V",
                );
                ui.horizontal(|ui| {
                    if ui.button("Confirm").clicked() {
                        import = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });
        if import {
            let parsed = serde_json::from_str::<RoutingConfig>(&text).or_else(|_| {
                serde_json::from_str::<Vec<Rule>>(&text).map(|rules| RoutingConfig {
                    rules,
                    ..self.config.clone()
                })
            });
            let result = parsed.map_err(anyhow::Error::from).and_then(|config| {
                anyhow::ensure!(
                    text.trim_start().starts_with('[')
                        || serde_json::from_str::<serde_json::Value>(&text)?
                            .get("rules")
                            .is_some(),
                    "Expected a routing configuration or rule array"
                );
                let mut profile = profile.clone();
                profile.routing = Some(config.clone());
                profile.block_ads = self.block_ads;
                Router::for_profile(&profile)?;
                Ok(config)
            });
            match result {
                Ok(config) => {
                    self.config = config;
                    self.selection.clear();
                    self.message = None;
                    return;
                }
                Err(error) => self.message = Some(format!("Import failed: {error:#}")),
            }
        }
        if open && !cancel {
            self.import_text = Some(text);
        }
    }

    fn test_dialog(&mut self, ctx: &egui::Context, profile: &Profile) {
        if !self.test_open {
            return;
        }
        let mut open = true;
        egui::Window::new("Test routing decision").id(egui::Id::new("routing-test")).default_width(580.0).collapsible(false).open(&mut open).show(ctx,|ui| {
            routing_style(ui);
            egui::Grid::new("routing-test-fields").show(ui,|ui| {
                ui.label("Host / IP");ui.text_edit_singleline(&mut self.test_host);ui.end_row();
                ui.label("Resolved IP(s)");ui.text_edit_singleline(&mut self.test_ips);ui.end_row();
            });
            ui.small("For a hostname's GeoIP test, enter its resolved IPs separated by commas. No network request is made.");
            if ui.button("Test route").clicked() {
                let mut profile=profile.clone();profile.routing=Some(self.normalized());profile.block_ads=self.block_ads;
                self.test_result=(|| -> anyhow::Result<String> {
                    anyhow::ensure!(!self.test_host.trim().is_empty(),"Enter a host or IP");
                    let ips=self.test_ips.split(',').map(str::trim).filter(|s|!s.is_empty()).map(str::parse).collect::<Result<Vec<std::net::IpAddr>,_>>()?;
                    let route=Router::for_profile(&profile)?.evaluate(self.test_host.trim(),&ips);
                    Ok(format!("{} — {}",outbound_label(route.outbound),route.rule))
                })().unwrap_or_else(|e|format!("{e:#}"));
            }
            ui.label(&self.test_result);
        });
        self.test_open = open;
    }
}

struct RuleEditor {
    index: Option<usize>,
    rule: Rule,
    domains: String,
    ips: String,
    process: String,
    country_search: String,
    site_search: String,
    auto_sort: bool,
    error: Option<String>,
}
impl RuleEditor {
    fn new(index: Option<usize>, rule: Rule) -> Self {
        Self {
            index,
            domains: rule.domains.join("\n"),
            ips: rule.ips.join("\n"),
            rule,
            process: String::new(),
            country_search: String::new(),
            site_search: String::new(),
            auto_sort: false,
            error: None,
        }
    }
    fn normalized(&self) -> Rule {
        let mut rule = self.rule.clone();
        rule.domains = lines(&self.domains);
        rule.ips = lines(&self.ips);
        if self.auto_sort {
            rule.domains.sort();
            rule.domains.dedup();
            rule.ips.sort();
            rule.ips.dedup();
        }
        rule
    }
}
fn lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .map(str::to_string)
        .collect()
}
fn outbound_label(value: Outbound) -> &'static str {
    match value {
        Outbound::Direct => "direct",
        Outbound::Proxy => "proxy",
        Outbound::Block => "block",
    }
}
fn outbound_picker(ui: &mut egui::Ui, id: &str, value: &mut Outbound, width: f32) {
    egui::ComboBox::from_id_salt(id)
        .width(width)
        .selected_text(outbound_label(*value))
        .show_ui(ui, |ui| {
            for action in [Outbound::Proxy, Outbound::Direct, Outbound::Block] {
                ui.selectable_value(value, action, outbound_label(action));
            }
        });
}
fn disabled_field(ui: &mut egui::Ui, hint: &str, width: f32) {
    let mut empty = String::new();
    ui.add_enabled(
        false,
        egui::TextEdit::singleline(&mut empty)
            .desired_width(width)
            .hint_text(hint),
    );
}
fn textarea(ui: &mut egui::Ui, id: &str, text: &mut String, height: f32, hint: &str) {
    egui::ScrollArea::vertical()
        .id_salt(id)
        .max_height(height)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add_sized(
                [ui.available_width(), height],
                egui::TextEdit::multiline(text)
                    .desired_width(f32::INFINITY)
                    .hint_text(hint),
            );
        });
}
fn geo_picker(
    ui: &mut egui::Ui,
    id: &str,
    label: &str,
    items: &[String],
    search: &mut String,
    text: &mut String,
    prefix: &str,
) {
    egui::ComboBox::from_id_salt(id)
        .width(ui.available_width())
        .selected_text(label)
        .show_ui(ui, |ui| {
            ui.add(egui::TextEdit::singleline(search).hint_text("Search…"));
            let search = search.to_ascii_lowercase();
            for item in items
                .iter()
                .filter(|v| v.to_ascii_lowercase().contains(&search))
            {
                if ui.selectable_label(false, item).clicked() {
                    append_pattern(text, &format!("{prefix}{}", item.to_ascii_lowercase()));
                }
            }
            if prefix == "geoip:" && ui.selectable_label(false, "Private / LAN").clicked() {
                append_pattern(text, "geoip:private");
            }
        });
}
fn append_pattern(text: &mut String, pattern: &str) {
    if !text.lines().any(|s| s.trim() == pattern) {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(pattern);
    }
}
fn cells(ui: &egui::Ui, rect: Rect, values: &[String; 4], widths: &[f32;4], color: Color32) {
    let mut x = rect.left();
    for (width, text) in widths.iter().zip(values) {
        let cell =
            Rect::from_min_size(egui::pos2(x, rect.top()), egui::vec2(*width, rect.height()));
        ui.painter()
            .rect_stroke(cell, 0, Stroke::new(0.5_f32, LINE), StrokeKind::Inside);
        let painter = ui
            .painter()
            .with_clip_rect(cell.shrink2(egui::vec2(5.0, 1.0)).intersect(ui.clip_rect()));
        painter.text(
            egui::pos2(x + 8.0, rect.center().y),
            egui::Align2::LEFT_CENTER,
            text,
            FontId::proportional(12.0),
            color,
        );
        x += width;
    }
}
fn routing_style(ui: &mut egui::Ui) {
    let style = ui.style_mut();
    style.spacing.item_spacing = egui::vec2(8.0, 4.0);
    style.spacing.interact_size.y = 26.0;
    style.spacing.scroll.floating = false;
    style.visuals.override_text_color = Some(Color32::from_gray(222));
    style.visuals.panel_fill = PANEL;
    style.visuals.window_fill = PANEL;
    style.visuals.selection.bg_fill = BLUE.gamma_multiply(0.45);
    style.visuals.selection.stroke = Stroke::new(1.0_f32, BLUE);
    style.visuals.window_corner_radius = egui::CornerRadius::same(8);
    for widget in [
        &mut style.visuals.widgets.inactive,
        &mut style.visuals.widgets.hovered,
        &mut style.visuals.widgets.active,
        &mut style.visuals.widgets.noninteractive,
    ] {
        widget.corner_radius = egui::CornerRadius::same(8);
    }
    style.override_font_id = Some(FontId::proportional(12.0));
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui::epaint::{Primitive, Shape};
    use serde_json::json;

    fn fixture() -> Profile {
        let mut profile = Profile::new("RVPN — Iran bypass");
        profile.mode = crate::profile::ConnMode::Proxy;
        profile.block_ads = false;
        let mut config = RoutingConfig::iran_direct();
        config.rules.insert(
            0,
            Rule {
                name: "Google services".into(),
                outbound: Outbound::Proxy,
                domains: vec!["geosite:google".into()],
                ..Rule::default()
            },
        );
        profile.routing = Some(config);
        profile
    }

    #[test]
    fn editing_is_staged_and_cancel_restores_last_confirmed_rules() {
        let profile = fixture();
        let mut draft = RoutingDraft::new(&profile);
        let original = draft.config.clone();
        let mut edit = RuleEditor::new(Some(0), draft.config.rules[0].clone());
        edit.rule.outbound = Outbound::Direct;
        assert_eq!(
            draft.config, original,
            "Editing must not mutate the routing configuration"
        );
        assert!(draft.accept_editor(&mut edit, &profile));
        assert_eq!(draft.config.rules[0].outbound, Outbound::Direct);
        draft.cancel();
        assert_eq!(draft.config, original);
        assert!(draft.accept_editor(&mut edit, &profile));
        draft.mark_saved();
        draft.config.rules.clear();
        draft.block_ads = true;
        draft.cancel();
        assert_eq!(draft.config.rules[0].outbound, Outbound::Direct);
        assert!(!draft.block_ads);
        let mut invalid = RuleEditor::new(None, Rule::default());
        let before = draft.config.clone();
        assert!(!draft.accept_editor(&mut invalid, &profile));
        assert_eq!(draft.config, before);
        assert!(invalid.error.is_some());
    }

    #[test]
    fn moving_multiple_rules_preserves_selection_order_and_priority() {
        let profile = fixture();
        let mut draft = RoutingDraft::new(&profile);
        draft.config.rules = (0..6)
            .map(|i| Rule {
                name: format!("rule-{i}"),
                domains: vec![format!("domain:example{i}.test")],
                ..Rule::default()
            })
            .collect();
        let ctx = egui::Context::default();
        draft.selection = BTreeSet::from([2, 3]);
        draft.action(Action::Up, &ctx);
        assert_eq!(draft.config.rules[1].name, "rule-2");
        assert_eq!(draft.config.rules[2].name, "rule-3");
        assert_eq!(draft.selection, BTreeSet::from([1, 2]));
        draft.action(Action::Bottom, &ctx);
        assert_eq!(draft.config.rules[4].name, "rule-2");
        assert_eq!(draft.config.rules[5].name, "rule-3");
        draft.action(Action::Top, &ctx);
        assert_eq!(draft.config.rules[0].name, "rule-2");
        assert_eq!(draft.config.rules[1].name, "rule-3");
        draft.action(Action::Remove, &ctx);
        assert_eq!(draft.config.rules.len(), 4);
        assert_eq!(draft.config.rules[0].name, "rule-0");
    }

    fn render(
        draft: &mut RoutingDraft,
        profile: &Profile,
        size: [f32; 2],
    ) -> (egui::Context, egui::FullOutput) {
        let ctx = egui::Context::default();
        ctx.set_visuals(egui::Visuals::dark());
        let input = || egui::RawInput {
            screen_rect: Some(Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(size[0], size[1]),
            )),
            ..Default::default()
        };
        let mut output = None;
        for _ in 0..4 {
            output = Some(ctx.run(input(), |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    draft.show(ui, profile);
                });
            }));
        }
        (ctx, output.unwrap())
    }
    fn texts(shape: &Shape, result: &mut Vec<(String, Rect)>) {
        match shape {
            Shape::Text(text) => result.push((
                text.galley.text().to_string(),
                text.galley.rect.translate(text.pos.to_vec2()),
            )),
            Shape::Vec(shapes) => {
                for shape in shapes {
                    texts(shape, result);
                }
            }
            _ => {}
        }
    }
    fn dump(ctx: &egui::Context, output: egui::FullOutput, size: [f32; 2], name: &str) {
        let Some(directory) = std::env::var_os("RVPN_UI_PREVIEW_DIR") else {
            return;
        };
        let font = ctx.fonts(|fonts| fonts.image());
        let pixels: Vec<_> = font.srgba_pixels(None).flat_map(|p| p.to_array()).collect();
        let meshes:Vec<_>=ctx.tessellate(output.shapes,output.pixels_per_point).into_iter().filter_map(|clipped| {
            let Primitive::Mesh(mesh)=clipped.primitive else {return None};
            Some(json!({"clip":[clipped.clip_rect.min.x,clipped.clip_rect.min.y,clipped.clip_rect.max.x,clipped.clip_rect.max.y],
                "vertices":mesh.vertices.iter().map(|v|json!([v.pos.x,v.pos.y,v.uv.x,v.uv.y,v.color.r(),v.color.g(),v.color.b(),v.color.a()])).collect::<Vec<_>>(),"indices":mesh.indices}))
        }).collect();
        let value = json!({"size":size,"atlas_size":font.size,"atlas_rgba":pixels,"meshes":meshes});
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join(format!("{name}.json")),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn headless_panel_and_details_layout_fit_and_export_previews() {
        let profile = fixture();
        let mut draft = RoutingDraft::new(&profile);
        let (ctx, output) = render(&mut draft, &profile, [1000.0, 740.0]);
        let mut labels = vec![];
        for shape in &output.shapes {
            texts(&shape.shape, &mut labels);
        }
        for label in [
            "Add Rule",
            "Domain strategy",
            "Rule List",
            "outboundTag",
            "Confirm",
            "Cancel",
        ] {
            assert!(
                labels.iter().any(|(text, _)| text.contains(label)),
                "Missing panel label: {label}"
            );
        }
        for (_, rect) in labels
            .iter()
            .filter(|(text, _)| text == "Confirm" || text == "Cancel")
        {
            assert!(rect.bottom() < 740.0, "Panel footer clipped: {rect:?}");
        }
        dump(&ctx, output, [1000.0, 740.0], "routing-panel");
        draft.selection = BTreeSet::from([1]);
        draft.action(Action::Edit, &ctx);
        let (ctx, output) = render(&mut draft, &profile, [1200.0, 820.0]);
        let mut labels = vec![];
        for shape in &output.shapes {
            texts(&shape.shape, &mut labels);
        }
        let mut groups = vec![];
        for label in ["Domain", "IP or IP CIDR", "Process (Linux/Windows)"] {
            groups.push(
                labels
                    .iter()
                    .find(|(text, _)| text == label)
                    .unwrap_or_else(|| panic!("Missing detail column {label}"))
                    .1,
            );
        }
        assert!((groups[0].top() - groups[1].top()).abs() < 2.0);
        assert!((groups[1].top() - groups[2].top()).abs() < 2.0);
        assert!(groups[0].left() < groups[1].left() && groups[1].left() < groups[2].left());
        for (_, rect) in labels
            .iter()
            .filter(|(text, _)| text == "Confirm" || text == "Cancel")
        {
            assert!(rect.bottom() < 820.0, "Details footer clipped: {rect:?}");
        }
        dump(&ctx, output, [1200.0, 820.0], "routing-rule-details");
    }
}
