//! System tray: state-coloured icon, context menu, click handling.
//!
//! The icon pixels are generated procedurally (a rounded shield with a
//! status dot) so no binary assets are needed and every state gets a
//! distinct colour at runtime.

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

const ICON_SIZE: u32 = 32;

/// RGBA icon bytes for a rounded shield with a status dot. Public so the
/// window icon can reuse the same artwork (see `main.rs`).
pub fn icon_rgba(accent: [u8; 3]) -> (Vec<u8>, u32, u32) {
    let w = ICON_SIZE;
    let h = ICON_SIZE;
    let mut rgba = Vec::with_capacity((w * h * 4) as usize);
    let radius = 8.0f32;
    let (cx, cy) = (w as f32 / 2.0, h as f32 / 2.0);
    for y in 0..h {
        for x in 0..w {
            let (xf, yf) = (x as f32 + 0.5, y as f32 + 0.5);
            // Rounded-rectangle distance (chebyshev-ish corner test).
            let dx = (xf - cx).abs() - (cx - radius).max(0.0);
            let dy = (yf - cy).abs() - (cy - radius).max(0.0);
            let outside = dx.max(dy) > radius.min(6.0);
            // Status dot: circle of radius 5 in the center.
            let dot = (xf - cx).hypot(yf - cy) <= 5.5;
            let mut px = [0, 0, 0, 0];
            if !outside {
                px = [accent[0], accent[1], accent[2], 255];
                if dot {
                    px = [255, 255, 255, 235];
                }
            }
            rgba.extend_from_slice(&px);
        }
    }
    (rgba, w, h)
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
    let (rgba, w, h) = icon_rgba(phase_accent(phase));
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
        let menu_tx = tx.clone();
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            match event.id().as_ref() {
                "show" => {
                    let _ = menu_tx.send(TrayCommand::ShowWindow);
                }
                "toggle" => {
                    let _ = menu_tx.send(TrayCommand::ToggleConnection);
                }
                "quit" => {
                    let _ = menu_tx.send(TrayCommand::Quit);
                }
                _ => {}
            }
        }));

        // Tray events (clicks) — left click opens the window.
        let tray_tx = tx.clone();
        TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
            if let TrayIconEvent::Click { button: tray_icon::MouseButton::Left, button_state: tray_icon::MouseButtonState::Up, .. } = event
            {
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
