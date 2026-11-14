//! In-memory + file logging: a tracing layer that feeds the GUI log view
//! and appends to a size-capped log file.

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tracing::Level;
use tracing_subscriber::layer::Layer;
use tracing_subscriber::prelude::*;

/// One formatted log line.
#[derive(Clone)]
pub struct LogEntry {
    pub time: chrono::DateTime<chrono::Local>,
    pub level: Level,
    pub message: String,
}

impl LogEntry {
    pub fn formatted(&self) -> String {
        format!(
            "{} {:>5}  {}",
            self.time.format("%H:%M:%S"),
            self.level.as_str(),
            self.message
        )
    }
}

/// Shared ring buffer the GUI polls.
#[derive(Clone, Default)]
pub struct LogRing {
    inner: Arc<Mutex<VecDeque<LogEntry>>>,
}

impl LogRing {
    const CAPACITY: usize = 4000;

    pub fn push(&self, entry: LogEntry) {
        let mut q = self.inner.lock().unwrap();
        if q.len() >= Self::CAPACITY {
            q.pop_front();
        }
        q.push_back(entry);
    }

    /// Snapshot of the newest `n` entries (oldest first).
    pub fn tail(&self, n: usize) -> Vec<LogEntry> {
        let q = self.inner.lock().unwrap();
        q.iter().rev().take(n).rev().cloned().collect()
    }

    /// Drop all entries.
    pub fn clear(&self) {
        self.inner.lock().unwrap().clear();
    }
}

/// Keep the on-disk log bounded: at 8 MiB rotate to `<path>.old` (matching
/// the upstream engine's policy) so a long session cannot fill the disk.
const LOG_FILE_MAX_BYTES: u64 = 8 * 1024 * 1024;

struct RingLayer {
    ring: LogRing,
    file: Mutex<Option<PathBuf>>,
    written: Mutex<u64>,
}

impl<S> Layer<S> for RingLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);

        let entry = LogEntry {
            time: chrono::Local::now(),
            level: *event.metadata().level(),
            message: visitor.0,
        };

        self.ring.push(entry.clone());

        let line = entry.formatted();
        let mut written = self.written.lock().unwrap();
        if let Some(path) = self.file.lock().unwrap().as_ref() {
            if *written >= LOG_FILE_MAX_BYTES {
                let _ = std::fs::rename(path, format!("{}.old", path.display()));
                *written = 0;
            }
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
                let _ = f.write_all(line.as_bytes());
                let _ = f.write_all(b"\n");
                *written += line.len() as u64 + 1;
            }
        }
    }
}

struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{:?}", value).trim_matches('"').to_string();
        } else if !self.0.is_empty() {
            self.0.push(' ');
            self.0.push_str(&format!("{}={:?}", field.name(), value));
        }
    }
}

/// Install the global subscriber. Idempotent; safe to call once at startup.
pub fn init(ring: &LogRing, file: Option<PathBuf>) {
    let layer = RingLayer {
        ring: ring.clone(),
        file: Mutex::new(file),
        written: Mutex::new(0),
    };
    // ERROR by default (mirrors the engine's default), override with
    // RVPN_LOG_LEVEL=trace|debug|info for diagnostics.
    let filter = match std::env::var("RVPN_LOG_LEVEL").as_deref() {
        Ok("trace") => tracing_subscriber::filter::LevelFilter::TRACE,
        Ok("debug") => tracing_subscriber::filter::LevelFilter::DEBUG,
        Ok("info") => tracing_subscriber::filter::LevelFilter::INFO,
        Ok("warn") => tracing_subscriber::filter::LevelFilter::WARN,
        _ => tracing_subscriber::filter::LevelFilter::INFO,
    };
    let _ = tracing_subscriber::registry().with(layer).with(filter).try_init();
}
