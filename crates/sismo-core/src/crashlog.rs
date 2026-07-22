// Copyright 2026 The Sismo Authors. All rights reserved.
// Licensed under the MIT License.

//! Crash-forensics breadcrumbs over `tracing`. `SISMO_CRASHLOG=<path>`
//! installs a global subscriber whose sink appends one line per event and
//! fsyncs before returning, so a hard machine lockup can be bracketed to the
//! exact phase that was in flight when the box died. Costs one fsync per
//! event — call sites are lifecycle edges, never per sample. When the var is
//! unset no subscriber is installed and every `tracing` macro is a no-op.
//!
//! The line format is shared with the difftest harness (which appends to the
//! same file from Python): `<unix_ms> <mono_ms> <pid> <message>`.

use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tracing::field::{Field, Visit};
use tracing::{span, Event, Metadata, Subscriber};

/// Install the fsync sink as the global `tracing` subscriber when
/// `SISMO_CRASHLOG` is set. Call once at process start; safe to call again.
pub fn init() {
    let Some(path) = std::env::var_os("SISMO_CRASHLOG") else { return };
    let Ok(file) = std::fs::OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    let _ = tracing::subscriber::set_global_default(FsyncSink {
        file: Mutex::new(file),
        t0: Instant::now(),
    });
}

struct FsyncSink {
    file: Mutex<std::fs::File>,
    t0: Instant,
}

impl Subscriber for FsyncSink {
    fn enabled(&self, _m: &Metadata<'_>) -> bool {
        true
    }

    fn event(&self, event: &Event<'_>) {
        let mut msg = String::new();
        event.record(&mut LineVisitor(&mut msg));
        let unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let mono_ms = self.t0.elapsed().as_millis();
        let mut f = self.file.lock().unwrap();
        let _ = writeln!(f, "{unix_ms} {mono_ms} {} {msg}", std::process::id());
        let _ = f.sync_data();
    }

    // Span plumbing is unused: breadcrumbs are point events.
    fn new_span(&self, _s: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }
    fn record(&self, _id: &span::Id, _r: &span::Record<'_>) {}
    fn record_follows_from(&self, _id: &span::Id, _f: &span::Id) {}
    fn enter(&self, _id: &span::Id) {}
    fn exit(&self, _id: &span::Id) {}
}

/// Renders `message` bare and every other field as ` key=value`.
struct LineVisitor<'a>(&'a mut String);

impl Visit for LineVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        } else {
            let _ = write!(self.0, " {}={value:?}", field.name());
        }
    }
}
