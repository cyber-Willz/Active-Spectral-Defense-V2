//! Real-time protection: watches one or more directories for create/modify
//! events and scans the affected file on the spot, logging (and optionally
//! quarantining) anything that comes back `Infected`. Mirrors the
//! "on-access scanning" model used by Defender's real-time protection and
//! similar tools, minus kernel-level filesystem minifilter hooks (which
//! require a signed driver and are out of scope for a userspace agent).
//!
//! This crate deliberately builds on `scanner-core::Scanner` rather than
//! re-implementing scanning -- every guard (archive-bomb limits, max file
//! size, PE heuristics, FIFO/socket rejection) that protects an on-demand
//! `rclam` scan also protects the real-time path here, with zero
//! duplicated logic to drift out of sync.

use notify::{Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rclam_quarantine::QuarantineManager;
use scanner_core::{Scanner, Verdict};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WatchError {
    #[error("failed to create filesystem watcher: {0}")]
    WatcherInit(String),
    #[error("failed to watch path {path}: {source}")]
    WatchPath {
        path: PathBuf,
        #[source]
        source: notify::Error,
    },
}

/// Behavior knobs for the monitor, kept separate from `clap::Args` so this
/// crate's `lib.rs` has no CLI dependency and can be driven directly by
/// tests or by another embedder.
#[derive(Debug, Clone)]
pub struct WatchConfig {
    /// Path prefixes; any event path lying under one of these (compared
    /// component-by-component via `Path::starts_with`, *not* a raw string
    /// prefix) is ignored outright -- never opened, never scanned. The
    /// quarantine directory itself should always be in this list --
    /// otherwise a monitor watching a parent directory would rescan its
    /// own quarantined (neutralized) copies forever.
    ///
    /// Component-wise comparison matters here: an excluded path of
    /// `/tmp` must not also exclude `/tmp2` just because the *string*
    /// `/tmp` is a prefix of the string `/tmp2` -- those are unrelated
    /// directories that happen to share a text prefix.
    pub excluded_paths: Vec<PathBuf>,
    /// File extensions (without the dot) that are never scanned.
    pub excluded_extensions: Vec<String>,
    /// Minimum time between two scans of the *same* path, to collapse the
    /// burst of events a single `write()` + `close()` typically produces.
    pub debounce: Duration,
    /// If true, a confirmed `Infected` verdict is immediately quarantined.
    /// If false, the monitor only logs -- useful for a dry-run / alert-only
    /// deployment before trusting the automation to touch files.
    pub auto_quarantine: bool,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            excluded_paths: Vec::new(),
            excluded_extensions: Vec::new(),
            debounce: Duration::from_millis(500),
            auto_quarantine: false,
        }
    }
}

impl WatchConfig {
    fn is_excluded(&self, path: &Path) -> bool {
        if self.excluded_paths.iter().any(|p| path.starts_with(p)) {
            return true;
        }
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if self
                .excluded_extensions
                .iter()
                .any(|e| e.eq_ignore_ascii_case(ext))
            {
                return true;
            }
        }
        false
    }
}

/// One thing the monitor did in reaction to a scanned file, returned from
/// `scan_and_react` so callers (tests, or a future UI) can observe outcomes
/// without scraping log output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReactionOutcome {
    Clean,
    /// Infected and (if `auto_quarantine` is set) successfully quarantined.
    Quarantined { detections: Vec<String>, quarantine_id: String },
    /// Infected but quarantine failed, or `auto_quarantine` was off.
    InfectedNotQuarantined { detections: Vec<String> },
    Skipped { reason: String },
    Error { message: String },
}

pub struct RealtimeMonitor {
    scanner: Arc<Scanner>,
    quarantine: Arc<QuarantineManager>,
    config: WatchConfig,
    running: Arc<AtomicBool>,
}

impl RealtimeMonitor {
    pub fn new(scanner: Arc<Scanner>, quarantine: Arc<QuarantineManager>, config: WatchConfig) -> Self {
        Self {
            scanner,
            quarantine,
            config,
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Returns a handle the caller can flip to `false` (e.g. from a Ctrl-C
    /// handler) to make [`Self::watch`] return.
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        self.running.clone()
    }

    /// Blocks the calling thread, watching `paths` recursively, until the
    /// handle from [`Self::stop_handle`] is cleared.
    pub fn watch(&self, paths: &[PathBuf]) -> Result<(), WatchError> {
        let (tx, rx) = channel::<notify::Result<Event>>();

        let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |res| {
            let _ = tx.send(res);
        })
        .map_err(|e| WatchError::WatcherInit(e.to_string()))?;

        watcher
            .configure(NotifyConfig::default())
            .map_err(|e| WatchError::WatcherInit(e.to_string()))?;

        for p in paths {
            watcher
                .watch(p, RecursiveMode::Recursive)
                .map_err(|e| WatchError::WatchPath {
                    path: p.clone(),
                    source: e,
                })?;
            tracing::info!(path = %p.display(), "real-time protection active");
        }

        let mut last_seen: HashMap<PathBuf, Instant> = HashMap::new();

        while self.running.load(Ordering::Relaxed) {
            match rx.recv_timeout(Duration::from_millis(250)) {
                Ok(Ok(event)) => self.handle_event(event, &mut last_seen),
                Ok(Err(e)) => tracing::warn!(error = %e, "filesystem watch error"),
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }

        tracing::info!("real-time protection stopped");
        Ok(())
    }

    fn handle_event(&self, event: Event, last_seen: &mut HashMap<PathBuf, Instant>) {
        let interesting = matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_));
        if !interesting {
            return;
        }

        for path in event.paths {
            if !path.is_file() || self.config.is_excluded(&path) {
                continue;
            }

            let now = Instant::now();
            if let Some(prev) = last_seen.get(&path) {
                if now.duration_since(*prev) < self.config.debounce {
                    continue;
                }
            }
            last_seen.insert(path.clone(), now);

            let outcome = self.scan_and_react(&path);
            log_outcome(&path, &outcome);
        }
    }

    /// Scans `path` and reacts to the verdict. Public (not just used from
    /// the event loop) so tests, and any future CLI "scan one file through
    /// the same code path the monitor uses," can call it directly.
    pub fn scan_and_react(&self, path: &Path) -> ReactionOutcome {
        // Give the writer a brief moment to finish flushing before we read;
        // avoids reading half-written files as a source of false negatives
        // (and, for large files, a source of spurious archive/PE parse
        // errors on a truncated in-progress write).
        std::thread::sleep(Duration::from_millis(50));

        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if let Some(pattern) = pe_analyze::suspicious_filename(name) {
                tracing::warn!(path = %path.display(), pattern = %pattern, "suspicious double-extension filename");
                // Fall through -- a double extension alone doesn't stop us
                // from still running signature/PE scanning below, since
                // the two signals are independent and both worth surfacing.
            }
        }

        // Read once. The same `data` is used for scanning below and, on a
        // detection, for quarantining -- deliberately not two separate
        // reads. `scan_path` (used by `rclam`/`rclamd`) mmaps the file
        // itself; that's the right choice for a one-shot scan, but for an
        // on-access monitor that may act on the result by moving the file,
        // reading once up front and passing the identical bytes through
        // removes the window where "what we scanned" and "what we
        // quarantined" could silently be two different sets of bytes.
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => return ReactionOutcome::Error { message: e.to_string() },
        };

        let reports = self.scanner.scan_in_memory(path, &data);

        // A single top-level path can produce multiple reports (e.g. it's
        // an archive with several members); react to the most severe
        // verdict among them, since "infected" always outranks "clean".
        let mut all_detections: Vec<String> = Vec::new();
        let mut skipped_reason: Option<String> = None;
        for r in &reports {
            match &r.verdict {
                Verdict::Infected(dets) => {
                    all_detections.extend(dets.iter().map(|d| d.name.clone()));
                }
                Verdict::LimitExceeded { detections, reason } => {
                    all_detections.extend(detections.iter().map(|d| d.name.clone()));
                    skipped_reason.get_or_insert_with(|| reason.clone());
                }
                Verdict::Skipped { reason } => {
                    skipped_reason.get_or_insert_with(|| reason.clone());
                }
                Verdict::Clean => {}
            }
        }

        if !all_detections.is_empty() {
            all_detections.sort();
            all_detections.dedup();

            if self.config.auto_quarantine {
                let sig_name = all_detections.join(", ");
                match self.quarantine.quarantine_bytes(path, &data, &sig_name) {
                    Ok(record) => {
                        // Only remove the original after the neutralized
                        // copy is confirmed written to disk (that's what
                        // quarantine_bytes just did) -- same
                        // crash-safety property `quarantine_file` gives
                        // callers that don't need to share the buffer.
                        if let Err(e) = std::fs::remove_file(path) {
                            tracing::error!(path = %path.display(), error = %e, "quarantined but failed to remove original");
                        }
                        return ReactionOutcome::Quarantined {
                            detections: all_detections,
                            quarantine_id: record.id,
                        };
                    }
                    Err(e) => {
                        tracing::error!(path = %path.display(), error = %e, "auto-quarantine failed");
                        return ReactionOutcome::InfectedNotQuarantined {
                            detections: all_detections,
                        };
                    }
                }
            }
            return ReactionOutcome::InfectedNotQuarantined {
                detections: all_detections,
            };
        }

        if let Some(reason) = skipped_reason {
            return ReactionOutcome::Skipped { reason };
        }

        ReactionOutcome::Clean
    }
}

fn log_outcome(path: &Path, outcome: &ReactionOutcome) {
    match outcome {
        ReactionOutcome::Clean => {}
        ReactionOutcome::Quarantined {
            detections,
            quarantine_id,
        } => {
            tracing::warn!(
                path = %path.display(),
                detections = ?detections,
                quarantine_id = %quarantine_id,
                "REAL-TIME DETECTION: quarantined"
            );
        }
        ReactionOutcome::InfectedNotQuarantined { detections } => {
            tracing::warn!(
                path = %path.display(),
                detections = ?detections,
                "REAL-TIME DETECTION: not quarantined (auto-quarantine disabled or failed)"
            );
        }
        ReactionOutcome::Skipped { reason } => {
            tracing::debug!(path = %path.display(), reason = %reason, "scan skipped");
        }
        ReactionOutcome::Error { message } => {
            tracing::debug!(path = %path.display(), error = %message, "scan error");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sig_engine::SignatureEngine;
    use std::fs;
    use tempfile::tempdir;

    fn scanner_with_test_sig() -> Arc<Scanner> {
        let engine = SignatureEngine::builder()
            .load_ndb("Sig.Test:74657374\n") // matches the bytes "test"
            .unwrap()
            .build();
        Arc::new(Scanner::new(engine))
    }

    #[test]
    fn clean_file_is_not_quarantined() {
        let src = tempdir().unwrap();
        let qdir = tempdir().unwrap();
        let path = src.path().join("clean.txt");
        fs::write(&path, b"nothing interesting here").unwrap();

        let monitor = RealtimeMonitor::new(
            scanner_with_test_sig(),
            Arc::new(QuarantineManager::new(qdir.path()).unwrap()),
            WatchConfig::default(),
        );

        assert_eq!(monitor.scan_and_react(&path), ReactionOutcome::Clean);
    }

    #[test]
    fn infected_file_is_quarantined_when_auto_quarantine_enabled() {
        let src = tempdir().unwrap();
        let qdir = tempdir().unwrap();
        let path = src.path().join("payload.bin");
        fs::write(&path, b"this contains a test marker").unwrap();

        let monitor = RealtimeMonitor::new(
            scanner_with_test_sig(),
            Arc::new(QuarantineManager::new(qdir.path()).unwrap()),
            WatchConfig {
                auto_quarantine: true,
                ..WatchConfig::default()
            },
        );

        let outcome = monitor.scan_and_react(&path);
        assert!(matches!(outcome, ReactionOutcome::Quarantined { .. }));
        assert!(!path.exists(), "infected file should be removed after quarantine");
    }

    #[test]
    fn infected_file_is_left_alone_when_auto_quarantine_disabled() {
        let src = tempdir().unwrap();
        let qdir = tempdir().unwrap();
        let path = src.path().join("payload.bin");
        fs::write(&path, b"this contains a test marker").unwrap();

        let monitor = RealtimeMonitor::new(
            scanner_with_test_sig(),
            Arc::new(QuarantineManager::new(qdir.path()).unwrap()),
            WatchConfig::default(), // auto_quarantine: false
        );

        let outcome = monitor.scan_and_react(&path);
        assert!(matches!(outcome, ReactionOutcome::InfectedNotQuarantined { .. }));
        assert!(path.exists(), "file must not be touched when auto-quarantine is off");
    }

    #[test]
    fn excluded_path_is_never_scanned() {
        let cfg = WatchConfig {
            excluded_paths: vec![PathBuf::from("/var/lib/rclam/quarantine")],
            ..WatchConfig::default()
        };
        assert!(cfg.is_excluded(Path::new("/var/lib/rclam/quarantine/foo.quar")));
        assert!(!cfg.is_excluded(Path::new("/home/user/file.txt")));
    }

    #[test]
    fn excluded_path_is_a_real_prefix_not_a_string_prefix() {
        // Regression test: excluding "/tmp" must not also exclude "/tmp2"
        // just because the two strings happen to share a text prefix --
        // they are unrelated directories.
        let cfg = WatchConfig {
            excluded_paths: vec![PathBuf::from("/tmp")],
            ..WatchConfig::default()
        };
        assert!(cfg.is_excluded(Path::new("/tmp/foo.bin")));
        assert!(
            !cfg.is_excluded(Path::new("/tmp2/foo.bin")),
            "excluding /tmp must not also exclude the unrelated directory /tmp2"
        );
    }

    #[test]
    fn excluded_extension_is_never_scanned() {
        let cfg = WatchConfig {
            excluded_extensions: vec!["log".to_string()],
            ..WatchConfig::default()
        };
        assert!(cfg.is_excluded(Path::new("/var/log/app.log")));
        assert!(!cfg.is_excluded(Path::new("/var/log/app.txt")));
    }
}
