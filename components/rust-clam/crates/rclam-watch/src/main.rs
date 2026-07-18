use clap::{Parser, Subcommand};
use rclam_quarantine::QuarantineManager;
use rclam_watch::{RealtimeMonitor, WatchConfig};
use scanner_core::{GuardLimits, Scanner};
use sig_engine::SignatureEngine;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "rclam-watch",
    about = "Real-time (on-access) protection and quarantine management for rust-clam"
)]
struct Cli {
    /// Path to a .ndb wildcard-signature database file. Repeatable.
    #[arg(long, global = true)]
    ndb: Vec<PathBuf>,
    /// Path to a .hdb hash-signature database file. Repeatable.
    #[arg(long, global = true)]
    hdb: Vec<PathBuf>,

    /// Directory neutralized detections are moved into.
    #[arg(long, global = true, default_value = "/var/lib/rclam/quarantine")]
    quarantine_dir: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start watching the given paths and scan every file that's created
    /// or modified underneath them.
    Watch {
        /// Directories to watch recursively.
        paths: Vec<PathBuf>,

        /// Directory (or file) path; any event path lying under it is
        /// never scanned. Matched as a real path prefix (component-wise),
        /// not a text/string prefix -- excluding `/tmp` does not also
        /// exclude `/tmp2`. Repeatable. The quarantine directory is
        /// always excluded automatically, so a monitor never rescans its
        /// own output.
        #[arg(long = "exclude-path")]
        exclude_path: Vec<PathBuf>,

        /// File extension (no dot) that's never scanned. Repeatable.
        #[arg(long = "exclude-ext")]
        exclude_ext: Vec<String>,

        /// Minimum milliseconds between two scans of the same path.
        #[arg(long, default_value_t = 500)]
        debounce_ms: u64,

        /// Automatically quarantine any confirmed detection. Off by
        /// default -- without it, the monitor only logs, which is the
        /// safer choice until the deployment is trusted to touch files
        /// on its own.
        #[arg(long)]
        auto_quarantine: bool,

        /// Maximum size, in bytes, of a single file scanned directly.
        #[arg(long, default_value_t = 200 * 1024 * 1024)]
        max_file_size: u64,

        /// Maximum nested-archive recursion depth.
        #[arg(long, default_value_t = 16)]
        max_depth: u32,
    },
    /// Manage previously quarantined items.
    Quarantine {
        #[command(subcommand)]
        action: QuarantineAction,
    },
}

#[derive(Subcommand)]
enum QuarantineAction {
    /// List everything currently in quarantine.
    List,
    /// Reverse neutralization and write a quarantined item back to disk.
    Restore {
        id: String,
        #[arg(long)]
        to: Option<PathBuf>,
    },
    /// Permanently delete a quarantined item.
    Delete { id: String },
    /// Check that a quarantined item's stored payload still authenticates
    /// against its recorded key/nonce and hash -- i.e. hasn't been
    /// corrupted or tampered with since quarantine. Writes nothing back
    /// to disk.
    Verify { id: String },
}

fn init_logging() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn load_engine(ndb: &[PathBuf], hdb: &[PathBuf]) -> std::io::Result<SignatureEngine> {
    let mut builder = SignatureEngine::builder();
    for p in ndb {
        let text = std::fs::read_to_string(p).map_err(|e| {
            tracing::error!(file = %p.display(), error = %e, "cannot read ndb file");
            e
        })?;
        builder = builder.load_ndb(&text).map_err(|e| {
            tracing::error!(file = %p.display(), error = %e, "failed to load ndb signatures");
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
        })?;
    }
    for p in hdb {
        let text = std::fs::read_to_string(p).map_err(|e| {
            tracing::error!(file = %p.display(), error = %e, "cannot read hdb file");
            e
        })?;
        builder = builder.load_hdb(&text).map_err(|e| {
            tracing::error!(file = %p.display(), error = %e, "failed to load hdb signatures");
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
        })?;
    }
    Ok(builder.build())
}

fn main() -> ExitCode {
    init_logging();
    let cli = Cli::parse();

    let quarantine = match QuarantineManager::new(&cli.quarantine_dir) {
        Ok(q) => Arc::new(q),
        Err(e) => {
            tracing::error!(error = %e, "failed to initialize quarantine store");
            return ExitCode::FAILURE;
        }
    };

    match cli.command {
        Commands::Watch {
            paths,
            exclude_path,
            exclude_ext,
            debounce_ms,
            auto_quarantine,
            max_file_size,
            max_depth,
        } => {
            if paths.is_empty() {
                eprintln!("rclam-watch: at least one path to watch is required");
                return ExitCode::FAILURE;
            }

            let engine = match load_engine(&cli.ndb, &cli.hdb) {
                Ok(e) => e,
                Err(_) => return ExitCode::FAILURE,
            };
            tracing::info!(
                wildcard_sigs = engine.hex_sig_count(),
                hash_sigs = engine.hash_sig_count(),
                "signature database loaded"
            );

            let limits = GuardLimits {
                max_depth,
                max_file_size,
                ..GuardLimits::default()
            };
            let scanner = Arc::new(Scanner::new(engine).with_limits(limits));

            // Always exclude the quarantine directory itself -- otherwise a
            // monitor watching one of its ancestors would rescan its own
            // neutralized output forever.
            let mut excluded_paths = exclude_path;
            excluded_paths.push(cli.quarantine_dir.clone());

            let config = WatchConfig {
                excluded_paths,
                excluded_extensions: exclude_ext,
                debounce: std::time::Duration::from_millis(debounce_ms),
                auto_quarantine,
            };

            if !auto_quarantine {
                tracing::info!(
                    "auto-quarantine is disabled: detections will be logged only, files left in place"
                );
            }

            let monitor = RealtimeMonitor::new(scanner, quarantine, config);
            let stop = monitor.stop_handle();
            if let Err(e) = ctrlc::set_handler(move || {
                tracing::info!("shutdown signal received, stopping real-time protection...");
                stop.store(false, Ordering::Relaxed);
            }) {
                tracing::error!(error = %e, "failed to install Ctrl-C handler");
                return ExitCode::FAILURE;
            }

            match monitor.watch(&paths) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    tracing::error!(error = %e, "real-time protection stopped with an error");
                    ExitCode::FAILURE
                }
            }
        }

        Commands::Quarantine { action } => match action {
            QuarantineAction::List => {
                let items = match quarantine.list() {
                    Ok(items) => items,
                    Err(e) => {
                        eprintln!("rclam-watch: failed to list quarantine: {e}");
                        return ExitCode::FAILURE;
                    }
                };
                if items.is_empty() {
                    println!("quarantine is empty");
                }
                for item in items {
                    println!(
                        "{}  {}  {}  ({} bytes, {})",
                        item.id,
                        item.quarantined_at.format("%Y-%m-%d %H:%M:%S UTC"),
                        item.original_path.display(),
                        item.file_size,
                        item.signature_name
                    );
                }
                ExitCode::SUCCESS
            }
            QuarantineAction::Restore { id, to } => match quarantine.restore(&id, to.as_deref()) {
                Ok(dest) => {
                    println!("restored to {}", dest.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("rclam-watch: restore failed: {e}");
                    ExitCode::FAILURE
                }
            },
            QuarantineAction::Delete { id } => match quarantine.delete(&id) {
                Ok(()) => {
                    println!("deleted {id}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("rclam-watch: delete failed: {e}");
                    ExitCode::FAILURE
                }
            },
            QuarantineAction::Verify { id } => match quarantine.verify(&id) {
                Ok(()) => {
                    println!("{id}: OK (authenticates, hash matches)");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    println!("{id}: FAILED ({e})");
                    ExitCode::FAILURE
                }
            },
        },
    }
}
