//! System tray: state-coloured icon, context menu, click handling.
//!
//! The icon pixels are drawn procedurally — the app logo (see `icon_rgba`)
//! with the shield in the phase colour — so no binary assets are needed and
//! every state gets a distinct colour at runtime.

use std::sync::mpsc;

use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{TrayIcon, TrayIconBuilder, TrayIconEvent};

use crate::engine::EnginePhase;

/// Commands the tray asks the app to run.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TrayCommand {
    ShowWindow,
    ToggleConnection,
    Quit,
}

/// Size of the tray icon; the window icon asks for [`WINDOW_ICON_SIZE`].
const ICON_SIZE: u32 = 32;
pub const WINDOW_ICON_SIZE: u32 = 64;

// Geometry of the logo in tile units (0..1 across the icon). The same values
// are drawn into assets/app.ico by scripts/make_icon.py.
const TILE_RADIUS: f32 = 0.21;
const TILE_TOP: [u8; 3] = [27, 37, 53];
const TILE_BOTTOM: [u8; 3] = [11, 15, 23];
const SHIELD_HALF_WIDTH: f32 = 0.27;
const SHIELD_TOP: f32 = 0.19;
const SHIELD_TIP: f32 = 0.84;
/// How quickly the sides curve in towards the tip.
const SHIELD_CURVE: f32 = 2.6;
const SHIELD_CORNER: f32 = 0.055;
/// Status dot: x, y, radius.
const DOT: (f32, f32, f32) = (0.5, 0.455, 0.075);

fn inside_tile(x: f32, y: f32) -> bool {
    let inset = 0.5 - TILE_RADIUS;
    let dx = (x - 0.5).abs() - inset;
    let dy = (y - 0.5).abs() - inset;
    dx.max(0.0).powi(2) + dy.max(0.0).powi(2) <= TILE_RADIUS * TILE_RADIUS
}

fn inside_shield(x: f32, y: f32) -> bool {
    let progress = (y - SHIELD_TOP) / (SHIELD_TIP - SHIELD_TOP);
    if !(0.0..=1.0).contains(&progress) {
        return false;
    }
    let half = SHIELD_HALF_WIDTH * (1.0 - progress.powf(SHIELD_CURVE)).max(0.0).sqrt();
    let (dx, dy) = ((x - 0.5).abs(), y - SHIELD_TOP);
    if dy < SHIELD_CORNER && dx > half - SHIELD_CORNER {
        let (cx, cy) = (half - SHIELD_CORNER, SHIELD_CORNER);
        return (dx - cx).powi(2) + (dy - cy).powi(2) <= SHIELD_CORNER * SHIELD_CORNER;
    }
    dx <= half
}

fn inside_dot(x: f32, y: f32) -> bool {
    (x - DOT.0).hypot(y - DOT.1) <= DOT.2
}

/// Colour of the logo at a tile-unit point, or `None` outside the tile.
fn logo_at(x: f32, y: f32, accent: [u8; 3]) -> Option<[u8; 3]> {
    if !inside_tile(x, y) {
        return None;
    }
    if inside_dot(x, y) {
        return Some([255, 255, 255]);
    }
    if inside_shield(x, y) {
        // A touch lighter towards the top, for a little depth.
        let up = ((SHIELD_TIP - y) / (SHIELD_TIP - SHIELD_TOP)).clamp(0.0, 1.0);
        return Some(std::array::from_fn(|i| (accent[i] as f32 + up * 26.0) as u8));
    }
    let down = y.clamp(0.0, 1.0);
    Some(std::array::from_fn(|i| {
        (TILE_TOP[i] as f32 + down * (TILE_BOTTOM[i] as f32 - TILE_TOP[i] as f32)) as u8
    }))
}

/// RGBA pixels of the app logo: the dark tile, a shield in `accent`, and the
/// white status dot. The tray passes the phase colour, the window the
/// connected green. Anti-aliased by averaging a 4x4 grid per pixel.
pub fn icon_rgba(accent: [u8; 3], size: u32) -> (Vec<u8>, u32, u32) {
    const GRID: u32 = 4;
    let cells = size * GRID;
    let samples = (GRID * GRID) as f32;
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);
    for py in 0..size {
        for px in 0..size {
            let (mut red, mut green, mut blue, mut cover) = (0f32, 0f32, 0f32, 0f32);
            for gy in 0..GRID {
                for gx in 0..GRID {
                    if let Some(c) = logo_at(
                        (px * GRID + gx) as f32 / cells as f32 + 0.5 / cells as f32,
                        (py * GRID + gy) as f32 / cells as f32 + 0.5 / cells as f32,
                        accent,
                    ) {
                        red += f32::from(c[0]);
                        green += f32::from(c[1]);
                        blue += f32::from(c[2]);
                        cover += 1.0;
                    }
                }
            }
            if cover == 0.0 {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
                continue;
            }
            let alpha = cover / samples;
            rgba.extend_from_slice(&[
                (red / cover) as u8,
                (green / cover) as u8,
                (blue / cover) as u8,
                (alpha * 255.0).round() as u8,
            ]);
        }
    }
    (rgba, size, size)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The opaque pixel at the centre of pixel (`x`, `y`).
    fn pixel(rgba: &[u8], size: u32, x: u32, y: u32) -> [u8; 4] {
        rgba[(y * size + x) as usize * 4..(y * size + x) as usize * 4 + 4].try_into().unwrap()
    }

    #[test]
    fn logo_is_a_tile_with_a_shield_and_a_dot() {
        let (rgba, w, h) = icon_rgba([46, 184, 114], 64);
        assert_eq!((w, h), (64, 64));
        assert_eq!(rgba.len(), 64 * 64 * 4);

        assert_eq!(pixel(&rgba, w, 1, 1)[3], 0, "the rounded corner is transparent");

        let above = pixel(&rgba, w, 32, 6);
        assert_eq!(above[3], 255, "the tile is opaque above the shield");
        assert!(above[0] < 60 && above[2] < 80, "and dark: {above:?}");
        let below = pixel(&rgba, w, 32, 60);
        assert_eq!(below[3], 255, "the tile is opaque below the tip");
        assert!(below[0] < 40, "and dark: {below:?}");

        let shield = pixel(&rgba, w, 20, 30);
        assert_eq!(shield[3], 255);
        assert!(
            shield[1] > 150 && shield[1] > shield[0] + 60 && shield[1] > shield[2] + 40,
            "the shield is green: {shield:?}"
        );

        assert_eq!(pixel(&rgba, w, 32, 29), [255, 255, 255, 255], "the status dot is white");
    }

    #[test]
    fn shield_takes_the_phase_colour() {
        let (rgba, w, _) = icon_rgba([214, 74, 74], 64);
        let shield = pixel(&rgba, w, 20, 30);
        assert!(
            shield[0] > 180 && shield[0] > shield[1] + 90,
            "a failed session turns the shield red: {shield:?}"
        );
    }

    /// Writes every phase colour of the 32 px logo to
    /// `<workspace>/target/logo-preview.bmp` (8x nearest neighbour), to look
    /// at the artwork that actually ships in the tray.
    #[test]
    #[ignore = "writes a preview bitmap"]
    fn logo_preview() {
        let states: [([u8; 3], &str); 5] = [
            ([90, 96, 112], "idle"),
            ([235, 175, 44], "connecting"),
            ([46, 184, 114], "connected"),
            ([214, 74, 74], "failed"),
            ([150, 96, 200], "stopping"),
        ];
        let scale = 8u32;
        let side = ICON_SIZE * scale;
        let (width, height) = (side * states.len() as u32, side);
        let icons: Vec<Vec<u8>> =
            states.iter().map(|(accent, _)| icon_rgba(*accent, ICON_SIZE).0).collect();

        let row_bytes = (width * 3 + 3) & !3;
        let mut bmp = Vec::new();
        bmp.extend_from_slice(b"BM");
        for value in [54 + row_bytes * height, 0, 54, 40] {
            bmp.extend_from_slice(&value.to_le_bytes());
        }
        bmp.extend_from_slice(&(width as i32).to_le_bytes());
        bmp.extend_from_slice(&(-(height as i32)).to_le_bytes());
        for value in [1u16, 24u16] {
            bmp.extend_from_slice(&value.to_le_bytes());
        }
        bmp.extend_from_slice(&[0; 24]); // rest of the BITMAPINFOHEADER
        for y in 0..height {
            for x in 0..width {
                let (index, inner) = ((x / side) as usize, x % side / scale);
                let at = ((y % side / scale) * ICON_SIZE + inner) as usize * 4;
                let rgba = &icons[index];
                bmp.extend_from_slice(&[rgba[at + 2], rgba[at + 1], rgba[at]]);
            }
            bmp.extend(std::iter::repeat(0).take((row_bytes - width * 3) as usize));
        }
        let out = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("../../target/logo-preview.bmp");
        std::fs::write(out, bmp).unwrap();
    }

    #[test]
    fn requested_size_is_honoured() {
        assert_eq!(icon_rgba([1, 2, 3], 16).1, 16);
        assert_eq!(icon_rgba([1, 2, 3], 64).2, 64);
    }
}

fn phase_accent(phase: &EnginePhase) -> [u8; 3] {
    match phase {
        EnginePhase::Idle => [90, 96, 112],      // slate — off
        EnginePhase::Starting | EnginePhase::Connecting { .. } => [235, 175, 44], // amber
        EnginePhase::Connected { .. } => [46, 184, 114],        // green
        EnginePhase::Failed { .. } => [214, 74, 74],            // red
        EnginePhase::Stopping => [150, 96, 200],                // violet
    }
}

fn make_icon(phase: &EnginePhase) -> tray_icon::Icon {
    let (rgba, w, h) = icon_rgba(phase_accent(phase), ICON_SIZE);
    tray_icon::Icon::from_rgba(rgba, w, h).expect("valid icon rgba")
}

/// The tray handle plus the internal channel the menu events flow through.
pub struct Tray {
    icon: TrayIcon,
    receiver: mpsc::Receiver<TrayCommand>,
    toggle_item: MenuItem,
    toggle_label: std::sync::Arc<std::sync::Mutex<String>>,
    last_accent: std::sync::Arc<std::sync::Mutex<[u8; 3]>>,
}

impl Tray {
    pub fn new(initial_phase: &EnginePhase) -> anyhow::Result<Self> {
        let (tx, rx) = mpsc::channel::<TrayCommand>();

        let show = MenuItem::with_id("show", "Open R-VPN", true, None);
        let toggle = MenuItem::with_id("toggle", "Connect", true, None);
        let quit = MenuItem::with_id("quit", "Quit", true, None);

        let menu = Menu::new();
        menu.append_items(&[&show, &toggle, &quit])?;

        let icon = make_icon(initial_phase);
        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("R-VPN")
            .with_icon(icon)
            .build()?;

        // Menu events arrive on muda's global channel; forward to ours.
        // The window-showing actions ALSO raise the window directly here:
        // while the window is hidden the egui loop may be stalled, so a
        // queued command alone might never be processed.
        let menu_tx = tx.clone();
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            match event.id().as_ref() {
                "show" => {
                    crate::platform::show_main_window();
                    let _ = menu_tx.send(TrayCommand::ShowWindow);
                }
                "toggle" => {
                    let _ = menu_tx.send(TrayCommand::ToggleConnection);
                }
                "quit" => {
                    // Same reason as "show": the command is only processed by
                    // the egui loop, which does not run while the window is
                    // hidden — un-stall it first or Quit is never seen and the
                    // app has to be killed from Task Manager.
                    crate::platform::show_main_window();
                    let _ = menu_tx.send(TrayCommand::Quit);
                }
                _ => {}
            }
        }));

        // Tray events (clicks) — left click opens the window (direct Win32,
        // independent of the egui repaint loop).
        let tray_tx = tx.clone();
        TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
            if let TrayIconEvent::Click { button: tray_icon::MouseButton::Left, button_state: tray_icon::MouseButtonState::Up, .. } = event
            {
                crate::platform::show_main_window();
                let _ = tray_tx.send(TrayCommand::ShowWindow);
            }
        }));

        Ok(Self {
            icon: tray,
            receiver: rx,
            toggle_item: toggle,
            toggle_label: std::sync::Arc::new(std::sync::Mutex::new("Connect".into())),
            last_accent: std::sync::Arc::new(std::sync::Mutex::new(phase_accent(initial_phase))),
        })
    }

    /// Poll pending tray commands (called once per UI frame).
    pub fn poll_commands(&self) -> Vec<TrayCommand> {
        let mut out = Vec::new();
        while let Ok(cmd) = self.receiver.try_recv() {
            out.push(cmd);
        }
        out
    }

    /// Refresh icon colour + toggle label from the engine phase.
    pub fn update_phase(&self, phase: &EnginePhase) {
        let label = match phase {
            EnginePhase::Idle | EnginePhase::Failed { .. } => "Connect",
            EnginePhase::Stopping => "Connect",
            _ => "Disconnect",
        };
        if let Ok(mut guard) = self.toggle_label.lock() {
            if *guard != label {
                *guard = label.to_string();
                self.toggle_item.set_text(label);
            }
        }
        let accent = phase_accent(phase);
        if let Ok(mut last) = self.last_accent.lock() {
            if *last != accent {
                *last = accent;
                let _ = self.icon.set_icon(Some(make_icon(phase)));
            }
        }
    }
}
