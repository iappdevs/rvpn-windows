//! Shared visual language and small, vector-drawn controls.
use eframe::egui::{self, Color32, FontId, Pos2, Rect, Response, RichText, Sense, Stroke, Vec2};

pub const BG: Color32 = Color32::from_rgb(13, 18, 28);
pub const SURFACE: Color32 = Color32::from_rgb(21, 30, 44);
pub const RAISED: Color32 = Color32::from_rgb(28, 40, 58);
pub const BORDER: Color32 = Color32::from_rgb(41, 55, 75);
pub const TEXT: Color32 = Color32::from_rgb(235, 242, 251);
pub const MUTED: Color32 = Color32::from_rgb(148, 166, 189);
pub const ACCENT: Color32 = Color32::from_rgb(111, 225, 199);
pub const BLUE: Color32 = Color32::from_rgb(150, 173, 255);

pub fn apply(ctx: &egui::Context) {
    let mut style = egui::Style::default();
    style.visuals = egui::Visuals::dark();
    let v = &mut style.visuals;
    v.override_text_color = Some(TEXT);
    v.panel_fill = BG;
    v.window_fill = SURFACE;
    v.extreme_bg_color = BG;
    v.faint_bg_color = RAISED;
    v.selection.bg_fill = Color32::from_rgb(35, 77, 77);
    v.selection.stroke = Stroke::new(1.0_f32, ACCENT);
    v.window_corner_radius = egui::CornerRadius::same(18);
    v.window_stroke = Stroke::new(1.0_f32, BORDER);
    v.widgets.inactive.bg_fill = RAISED;
    v.widgets.inactive.weak_bg_fill = RAISED;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    v.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, TEXT);
    v.widgets.hovered.bg_fill = Color32::from_rgb(36, 55, 74);
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(36, 55, 74);
    v.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, ACCENT.gamma_multiply(0.6));
    v.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, TEXT);
    v.widgets.active.bg_fill = Color32::from_rgb(37, 77, 77);
    v.widgets.active.weak_bg_fill = v.widgets.active.bg_fill;
    v.widgets.active.fg_stroke = Stroke::new(1.0_f32, ACCENT);
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, MUTED);
    for widget in [
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.noninteractive,
    ] {
        widget.corner_radius = egui::CornerRadius::same(9);
    }
    style.spacing.item_spacing = egui::vec2(10.0, 9.0);
    style.spacing.button_padding = egui::vec2(14.0, 9.0);
    style.spacing.interact_size.y = 34.0;
    style.spacing.window_margin = egui::Margin::same(22);
    style.spacing.scroll.floating = false;
    style
        .text_styles
        .insert(egui::TextStyle::Heading, FontId::proportional(30.0));
    style
        .text_styles
        .insert(egui::TextStyle::Body, FontId::proportional(14.0));
    style
        .text_styles
        .insert(egui::TextStyle::Button, FontId::proportional(14.0));
    style
        .text_styles
        .insert(egui::TextStyle::Small, FontId::proportional(12.0));
    ctx.set_style(style);
}

pub fn card() -> egui::Frame {
    egui::Frame::NONE
        .fill(SURFACE)
        .stroke(Stroke::new(1.0_f32, BORDER))
        .corner_radius(18)
        .inner_margin(22)
}
pub fn heading(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(RichText::new(title).size(30.0).strong().color(TEXT));
    ui.label(RichText::new(subtitle).color(MUTED));
    ui.add_space(18.0);
}
pub fn section(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(RichText::new(title).size(17.0).strong().color(TEXT));
    if !subtitle.is_empty() {
        ui.label(RichText::new(subtitle).small().color(MUTED));
    }
    ui.add_space(6.0);
}
pub fn primary(ui: &mut egui::Ui, label: &str) -> Response {
    ui.add(
        egui::Button::new(RichText::new(label).strong().color(BG))
            .fill(ACCENT)
            .min_size(egui::vec2(126.0, 38.0)),
    )
}
pub fn pill(ui: &mut egui::Ui, text: &str, color: Color32) {
    let galley = ui
        .painter()
        .layout_no_wrap(text.into(), FontId::proportional(11.0), color);
    let size = galley.size() + egui::vec2(20.0, 10.0);
    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
    ui.painter()
        .rect_filled(rect, 20, color.gamma_multiply(0.12));
    ui.painter()
        .galley(rect.min + egui::vec2(10.0, 5.0), galley, color);
}
pub fn toggle(ui: &mut egui::Ui, value: &mut bool, title: &str, hint: &str) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        let width = (ui.available_width() - 68.0).max(100.0);
        ui.allocate_ui_with_layout(
            egui::vec2(width, 46.0),
            egui::Layout::top_down(egui::Align::LEFT),
            |ui| {
                ui.set_width(width);
                ui.label(RichText::new(title).strong().color(TEXT));
                ui.label(RichText::new(hint).small().color(MUTED));
            },
        );
        let (rect, response) = ui.allocate_exact_size(egui::vec2(44.0, 26.0), Sense::click());
        if response.clicked() {
            *value = !*value;
            changed = true;
        }
        response.widget_info(|| {
            egui::WidgetInfo::selected(egui::WidgetType::Checkbox, ui.is_enabled(), *value, title)
        });
        let t = ui.ctx().animate_bool_responsive(response.id, *value);
        ui.painter()
            .rect_filled(rect, 20, if *value { ACCENT } else { BORDER });
        ui.painter().circle_filled(
            egui::pos2(rect.left() + 13.0 + 18.0 * t, rect.center().y),
            9.0,
            if *value { BG } else { MUTED },
        );
    });
    changed
}

#[derive(Clone, Copy)]
pub enum Icon {
    Power,
    Servers,
    Route,
    Settings,
    Activity,
    Shield,
}
pub fn icon(ui: &egui::Ui, rect: Rect, kind: Icon, color: Color32) {
    let p = ui.painter();
    let s = Stroke::new(1.7_f32, color);
    let at = |x: f32, y: f32| {
        Pos2::new(
            rect.left() + rect.width() * x,
            rect.top() + rect.height() * y,
        )
    };
    let line = |a: (f32, f32), b: (f32, f32)| {
        p.line_segment([at(a.0, a.1), at(b.0, b.1)], s);
    };
    match kind {
        Icon::Power => {
            let points = (0..=40)
                .map(|i| {
                    let a = 0.70 + (std::f32::consts::TAU - 1.40) * i as f32 / 40.0;
                    at(0.5 + 0.32 * a.sin(), 0.51 - 0.32 * a.cos())
                })
                .collect();
            p.add(egui::Shape::line(points, s));
            line((0.5, 0.08), (0.5, 0.48));
        }
        Icon::Shield => {
            p.add(egui::Shape::closed_line(
                vec![
                    at(0.5, 0.09),
                    at(0.83, 0.23),
                    at(0.78, 0.64),
                    at(0.5, 0.9),
                    at(0.22, 0.64),
                    at(0.17, 0.23),
                ],
                s,
            ));
            line((0.34, 0.49), (0.46, 0.61));
            line((0.46, 0.61), (0.68, 0.37));
        }
        Icon::Servers => {
            for y in [0.12, 0.55] {
                p.rect_stroke(
                    Rect::from_min_max(at(0.12, y), at(0.88, y + 0.3)),
                    3,
                    s,
                    egui::StrokeKind::Inside,
                );
                p.circle_filled(at(0.26, y + 0.15), 1.6, color);
                line((0.48, y + 0.15), (0.72, y + 0.15));
            }
        }
        Icon::Route => {
            line((0.22, 0.25), (0.72, 0.25));
            line((0.72, 0.25), (0.72, 0.75));
            line((0.72, 0.75), (0.25, 0.75));
            for (x, y) in [(0.22, 0.25), (0.25, 0.75)] {
                p.circle_filled(at(x, y), 3.0, color);
            }
        }
        Icon::Settings => {
            for (x, y) in [(0.25, 0.32), (0.5, 0.66), (0.75, 0.42)] {
                line((x, 0.13), (x, 0.87));
                p.circle_filled(at(x, y), 3.5, SURFACE);
                p.circle_stroke(at(x, y), 3.5, s);
            }
        }
        Icon::Activity => {
            p.add(egui::Shape::line(
                vec![
                    at(0.07, 0.55),
                    at(0.28, 0.55),
                    at(0.4, 0.18),
                    at(0.59, 0.83),
                    at(0.72, 0.45),
                    at(0.93, 0.45),
                ],
                s,
            ));
        }
    }
}
pub fn nav(ui: &mut egui::Ui, label: &str, kind: Icon, selected: bool) -> Response {
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 48.0), Sense::click());
    if selected || response.hovered() {
        ui.painter().rect_filled(
            rect,
            10,
            if selected {
                Color32::from_rgb(29, 57, 60)
            } else {
                SURFACE
            },
        );
    }
    if selected {
        ui.painter().rect_filled(
            Rect::from_min_size(rect.min + egui::vec2(0.0, 14.0), egui::vec2(3.0, 20.0)),
            3,
            ACCENT,
        );
    }
    let color = if selected { ACCENT } else { MUTED };
    icon(
        ui,
        Rect::from_min_size(rect.min + egui::vec2(16.0, 13.0), Vec2::splat(22.0)),
        kind,
        color,
    );
    ui.painter().text(
        rect.min + egui::vec2(52.0, 24.0),
        egui::Align2::LEFT_CENTER,
        label,
        FontId::proportional(14.0),
        color,
    );
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::SelectableLabel,
            ui.is_enabled(),
            selected,
            label,
        )
    });
    response
}
