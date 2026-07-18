//! ClamAV scan -> Quarantine action lane (the diagram's middle branch).
//!
//! `siem-correlation-bridge`'s own docs are explicit that `active-siem`
//! has no real file-scanning component behind `ClamAvSender` (see
//! `components/active-siem/crates/siem-correlation-bridge/src/lib.rs`'s
//! module docs, point 1: "`ClamAvSender` has no real detector behind it
//! in this codebase"). This crate is that missing detector: it drives
//! `rust-clam`'s real `scanner_core::Scanner` and
//! `rclam_quarantine::QuarantineManager` (see
//! `components/rust-clam/crates/scanner-core` and `.../rclam-quarantine`)
//! against a set of watched directories and submits what it finds.
//!
//! # Host attribution
//!
//! `siem_correlation` keys evidence on `host: IpAddr`, but a file scan is
//! inherently host-agnostic -- `rust-clam`'s own `rclam-watch` crate has
//! no concept of "which host this file came from" (see its crate docs).
//! Real deployments attach that context differently depending on where
//! the file entered the network (an SMTP relay's per-sender maildir, an
//! FTP/SMB drop directory keyed by source host, a download proxy's
//! per-client cache). This crate makes that mapping an explicit,
//! configured input -- [`HostWatchTarget`] pairs one watched directory
//! with the host its files should be attributed to -- rather than
//! guessing or fabricating a host.
//!
//! # Honest gaps
//!
//! - This does not reuse `rclam_watch::RealtimeMonitor::watch()` (its
//!   event loop has no hook for "and also tell someone else what
//!   happened" -- see that crate's `handle_event`), so it re-implements
//!   the same `notify`-based debounce-and-scan loop directly against
//!   `Scanner`/`QuarantineManager` instead. The scanning and quarantine
//!   logic itself is not reimplemented -- both come straight from
//!   `rust-clam`.

use notify::{Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rclam_quarantine::QuarantineManager;
use scanner_core::{Scanner, Verdict};
use siem_correlation::ClamAvSender;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

/// One watched directory and the host its files are attributed to.
#[derive(Debug, Clone)]
pub struct HostWatchTarget {
    pub path: PathBuf,
    pub host: IpAddr,
}

#[derive(Debug, Error)]
pub enum ClamAvLaneError {
    #[error("failed to create filesystem watcher: {0}")]
    WatcherInit(String),
    #[error("failed to watch path {path}: {source}")]
    WatchPath {
        path: PathBuf,
        #[source]
        source: notify::Error,
    },
}

/// Blocks the calling thread, watching every `target.path` for
/// create/modify events, scanning affected files with `scanner`, and
/// quarantining infected ones with `quarantine`. Submits one
/// `ClamAvSender` event per reacted-to file. Intended to be run on its
/// own `std::thread` by the orchestrator (see `orchestrator/src/main.rs`)
/// -- `notify` and `Scanner::scan_in_memory` are both synchronous.
pub fn run(
    targets: &[HostWatchTarget],
    scanner: Arc<Scanner>,
    quarantine: Arc<QuarantineManager>,
    clamav: ClamAvSender,
    running: Arc<AtomicBool>,
) -> Result<(), ClamAvLaneError> {
    let host_by_path: HashMap<PathBuf, IpAddr> =
        targets.iter().map(|t| (t.path.clone(), t.host)).collect();

    let (tx, rx) = channel::<notify::Result<Event>>();
    let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })
    .map_err(|e| ClamAvLaneError::WatcherInit(e.to_string()))?;
    watcher
        .configure(NotifyConfig::default())
        .map_err(|e| ClamAvLaneError::WatcherInit(e.to_string()))?;

    for target in targets {
        watcher
            .watch(&target.path, RecursiveMode::NonRecursive)
            .map_err(|e| ClamAvLaneError::WatchPath { path: target.path.clone(), source: e })?;
        tracing::info!(path = %target.path.display(), host = %target.host, "asd-clamav-bridge: watching");
    }

    let debounce = Duration::from_millis(500);
    let mut last_seen: HashMap<PathBuf, Instant> = HashMap::new();

    while running.load(Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(Ok(event)) => {
                if !matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                    continue;
                }
                for path in event.paths {
                    if !path.is_file() {
                        continue;
                    }
                    let now = Instant::now();
                    if let Some(prev) = last_seen.get(&path) {
                        if now.duration_since(*prev) < debounce {
                            continue;
                        }
                    }
                    last_seen.insert(path.clone(), now);

                    let Some(parent) = path.parent() else { continue };
                    let Some(&host) = host_by_path.get(parent) else {
                        tracing::warn!(path = %path.display(), "asd-clamav-bridge: file under unmapped directory, skipping");
                        continue;
                    };

                    scan_react_and_submit(&path, host, &scanner, &quarantine, &clamav);
                }
            }
            Ok(Err(e)) => tracing::warn!(error = %e, "asd-clamav-bridge: filesystem watch error"),
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    Ok(())
}

fn scan_react_and_submit(
    path: &std::path::Path,
    host: IpAddr,
    scanner: &Scanner,
    quarantine: &QuarantineManager,
    clamav: &ClamAvSender,
) {
    // Brief settle delay, same rationale as rclam-watch's own monitor:
    // avoid reading a half-written file as a false negative.
    std::thread::sleep(Duration::from_millis(50));

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "asd-clamav-bridge: read failed");
            return;
        }
    };

    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("<unknown>").to_string();

    let reports = scanner.scan_in_memory(path, &data);
    let worst_detections = reports.iter().find_map(|r| match &r.verdict {
        Verdict::Infected(d) => Some(d.clone()),
        Verdict::LimitExceeded { detections, .. } if !detections.is_empty() => Some(detections.clone()),
        _ => None,
    });

    let Some(detections) = worst_detections else {
        return; // clean or skipped -- nothing to correlate on
    };

    let signature_names: Vec<String> = detections.iter().map(|d| d.name.clone()).collect();
    let signature = signature_names.join(", ");

    let quarantined = quarantine.quarantine_bytes(path, &data, &signature).is_ok()
        && std::fs::remove_file(path).is_ok();
    if quarantined {
        tracing::warn!(path = %path.display(), %signature, "asd-clamav-bridge: quarantined");
    } else {
        tracing::error!(path = %path.display(), %signature, "asd-clamav-bridge: detected but quarantine failed");
    }

    clamav.submit(host, file_name, signature, quarantined);
}
