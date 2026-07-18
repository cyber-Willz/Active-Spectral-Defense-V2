//! TOML-loadable configuration for the orchestrator. See
//! `asd.example.toml` at the repo root for a documented example of every
//! field here, and `README.md`'s "Wiring it up for real" for what each
//! path/value needs to point at in a live deployment.

use serde::Deserialize;
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct AsdConfig {
    pub nsm: NsmConfig,
    pub firewall: FirewallConfig,
    pub clamav: ClamAvConfig,
    pub spectral: SpectralConfig,
    pub response: ResponseConfig,
}

/// NSM fast-path lane: where its NDJSON alert stream lands, and where its
/// XDP control socket listens.
#[derive(Debug, Clone, Deserialize)]
pub struct NsmConfig {
    /// Path `nsm`'s stdout is redirected to, e.g. started as
    /// `nsm --simulate --xdp --xdp-control-socket <control_socket_path>
    ///  > <alert_log_path>`.
    pub alert_log_path: PathBuf,
    pub control_socket_path: PathBuf,
}

/// Perimeter firewall rule-sync target.
#[derive(Debug, Clone, Deserialize)]
pub struct FirewallConfig {
    /// The exact config path rustwall was started with
    /// (`rustwall --config <this path>`). This orchestrator rewrites it
    /// in place -- see `asd-firewall-sync`'s docs on why a dedicated,
    /// ASD-managed file is strongly recommended over a hand-annotated
    /// one.
    pub config_path: PathBuf,
    pub pid: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClamAvConfig {
    pub quarantine_dir: PathBuf,
    /// ClamAV-style `.ndb` (extended signature) files to load.
    #[serde(default)]
    pub signature_ndb_paths: Vec<PathBuf>,
    /// `.hdb` (hash signature) files to load.
    #[serde(default)]
    pub signature_hdb_paths: Vec<PathBuf>,
    pub watch_targets: Vec<WatchTargetConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WatchTargetConfig {
    pub path: PathBuf,
    pub host: IpAddr,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SpectralConfig {
    /// e.g. "http://localhost:6334" -- see spec_engine's own README for
    /// running Qdrant (`docker run -p 6333:6333 -p 6334:6334
    /// qdrant/qdrant`).
    pub qdrant_url: String,
    #[serde(default = "default_blast_depth")]
    pub blast_radius_depth: usize,
}

fn default_blast_depth() -> usize {
    2
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResponseConfig {
    /// One of "info", "low", "medium", "high", "critical" -- the floor
    /// `siem_response::ResponsePolicy` requires before it will act, even
    /// after a verdict has already cleared the review gate.
    #[serde(default = "default_min_severity")]
    pub min_severity: String,
    /// Hosts `ResponsePolicy` will never auto-block, regardless of
    /// verdict.
    #[serde(default)]
    pub allowlist: Vec<String>,
    #[serde(default = "default_ttl")]
    pub xdp_block_ttl_secs: u64,
}

fn default_min_severity() -> String {
    "high".to_string()
}

fn default_ttl() -> u64 {
    3600
}

impl AsdConfig {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading config {}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| anyhow::anyhow!("parsing config {}: {e}", path.display()))
    }
}
