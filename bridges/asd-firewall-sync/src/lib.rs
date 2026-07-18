//! Closes the diagram's "rule sync" feedback arrow: XDP enforcement /
//! containment, once a host is *confirmed* malicious, syncs that IP back
//! up to the perimeter firewall (`rustwall`) as a coarse upstream block --
//! see `architecture_with_firewall_perimeter.svg`'s description: "confirmed
//! -malicious IPs from XDP enforcement sync back up to the firewall as
//! coarse upstream rules."
//!
//! # Why this crate exists rather than an API call into rustwall
//!
//! `rustwall` (see `components/firewall-perimeter`) is a `[[bin]]`-only
//! crate with no `[lib]` target, and its only externally reachable admin
//! surface is `POST /quarantine/unban/<ip>` (removal, not addition -- see
//! `metrics.rs`). There is no "ban this IP" RPC. What it *does* have is a
//! hot config reload on `SIGHUP` that swaps `Engine` (rule set + aliases)
//! without dropping conntrack/quarantine state (`main.rs`'s signal
//! handler, `Config::load`). So the integration point this crate uses is
//! the same one a human operator would: rewrite the policy file, then
//! signal the process to pick it up.
//!
//! # What it does
//!
//! rustwall's config format already has exactly the primitive this needs
//! -- a named, reusable CIDR set referenced from a rule (the pfSense/
//! OPNsense "alias" pattern; see `rustwall.example.toml`). This crate:
//!
//! 1. Parses rustwall's TOML config as a generic [`toml::Value`] (not
//!    rustwall's own `Config` struct -- this crate has no dependency on
//!    `firewall-perimeter` at all, matching the rest of this integration
//!    layer's preference for loose, file/socket-level coupling over
//!    reaching into another component's internals).
//! 2. Ensures an alias named [`CONFIRMED_MALICIOUS_ALIAS`] exists, and
//!    replaces its `cidrs` with the current confirmed-host set (each host
//!    as a `/32`).
//! 3. Ensures a `drop` rule referencing that alias exists as the **first**
//!    rule in the list (rustwall evaluates top-to-bottom, first match
//!    wins -- see `rustwall.example.toml`'s header comment -- so this rule
//!    must stay ahead of any `accept` rule an operator adds later).
//! 4. Writes the file back atomically (write-to-temp + rename) and sends
//!    `SIGHUP` to the supplied rustwall PID.
//!
//! # Honest gaps
//!
//! - Round-tripping through `toml::Value` does not preserve comments or
//!   key ordering elsewhere in the file. Fine for a config this crate
//!   owns end-to-end; if you hand-maintain a heavily-commented rustwall
//!   config, point this crate at a dedicated ASD-managed file instead of
//!   your annotated one (rustwall has no `include` mechanism, so it has
//!   to be one file -- see `README.md`).
//! - Sending `SIGHUP` via the `kill` binary rather than a signals crate
//!   keeps this crate dependency-light; it requires `kill` on `$PATH`
//!   (true on any Linux rustwall would itself run on) and that the
//!   orchestrator process has permission to signal rustwall's PID (same
//!   user, or `CAP_KILL`/root).

use serde::Deserialize;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const CONFIRMED_MALICIOUS_ALIAS: &str = "asd_confirmed_malicious";
pub const CONFIRMED_MALICIOUS_RULE: &str = "asd-confirmed-malicious-block";

#[derive(Debug, Error)]
pub enum FirewallSyncError {
    #[error("reading rustwall config at {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing rustwall config at {path} as TOML: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("rustwall config at {path} is not a TOML table at the top level")]
    NotATable { path: PathBuf },
    #[error("serializing updated rustwall config: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("writing rustwall config at {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("signaling rustwall (pid {pid}) to reload: {source}")]
    Signal {
        pid: u32,
        #[source]
        source: std::io::Error,
    },
    #[error("`kill -HUP {pid}` exited with status {status}")]
    SignalNonZero { pid: u32, status: std::process::ExitStatus },
}

/// Handle bundling everything needed to keep rustwall's perimeter policy
/// in sync with confirmed-malicious hosts.
#[derive(Debug, Clone)]
pub struct FirewallSyncTarget {
    /// Path to the rustwall TOML config file this rustwall instance was
    /// (or will be, on next SIGHUP) launched with `--config <this path>`.
    pub config_path: PathBuf,
    /// PID of the running rustwall process, signaled on every sync.
    pub pid: u32,
}

/// Rewrites `target.config_path`'s `asd_confirmed_malicious` alias to
/// exactly `hosts`, ensures the blocking rule referencing it is first in
/// the rule list, and SIGHUPs rustwall to reload. `hosts` should be the
/// orchestrator's full current confirmed-malicious set (this is a
/// replace, not an append -- callers own eviction/expiry of hosts that
/// are no longer considered malicious).
pub fn sync_confirmed_hosts(
    target: &FirewallSyncTarget,
    hosts: &[IpAddr],
) -> Result<(), FirewallSyncError> {
    let mut doc = load(&target.config_path)?;
    upsert_alias(&mut doc, hosts);
    upsert_blocking_rule(&mut doc);
    save(&target.config_path, &doc)?;
    reload(target.pid)?;
    Ok(())
}

fn load(path: &Path) -> Result<toml::Value, FirewallSyncError> {
    let text = fs::read_to_string(path).map_err(|source| FirewallSyncError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let value: toml::Value = toml::from_str(&text).map_err(|source| FirewallSyncError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    if !value.is_table() {
        return Err(FirewallSyncError::NotATable { path: path.to_path_buf() });
    }
    Ok(value)
}

fn save(path: &Path, doc: &toml::Value) -> Result<(), FirewallSyncError> {
    let text = toml::to_string_pretty(doc)?;
    let tmp = path.with_extension("toml.asd-tmp");
    fs::write(&tmp, text).map_err(|source| FirewallSyncError::Write {
        path: tmp.clone(),
        source,
    })?;
    fs::rename(&tmp, path).map_err(|source| FirewallSyncError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn reload(pid: u32) -> Result<(), FirewallSyncError> {
    let status = std::process::Command::new("kill")
        .args(["-HUP", &pid.to_string()])
        .status()
        .map_err(|source| FirewallSyncError::Signal { pid, source })?;
    if !status.success() {
        return Err(FirewallSyncError::SignalNonZero { pid, status });
    }
    tracing::info!(pid, "rustwall: sent SIGHUP to reload asd_confirmed_malicious alias");
    Ok(())
}

fn upsert_alias(doc: &mut toml::Value, hosts: &[IpAddr]) {
    let mut cidrs: Vec<String> = hosts.iter().map(|ip| format!("{ip}/32")).collect();
    cidrs.sort();
    cidrs.dedup();

    let table = doc.as_table_mut().expect("checked in load()");
    let aliases = table
        .entry("aliases")
        .or_insert_with(|| toml::Value::Array(Vec::new()))
        .as_array_mut()
        .expect("`aliases` in a rustwall config must be an array of tables");

    let existing = aliases.iter_mut().find(|a| {
        a.get("name").and_then(|n| n.as_str()) == Some(CONFIRMED_MALICIOUS_ALIAS)
    });

    let cidrs_value = toml::Value::Array(cidrs.into_iter().map(toml::Value::String).collect());
    match existing {
        Some(alias) => {
            alias
                .as_table_mut()
                .expect("alias entries are tables")
                .insert("cidrs".to_string(), cidrs_value);
        }
        None => {
            let mut new_alias = toml::map::Map::new();
            new_alias.insert("name".to_string(), toml::Value::String(CONFIRMED_MALICIOUS_ALIAS.to_string()));
            new_alias.insert("cidrs".to_string(), cidrs_value);
            aliases.push(toml::Value::Table(new_alias));
        }
    }
}

fn upsert_blocking_rule(doc: &mut toml::Value) {
    let table = doc.as_table_mut().expect("checked in load()");
    let rules = table
        .entry("rules")
        .or_insert_with(|| toml::Value::Array(Vec::new()))
        .as_array_mut()
        .expect("`rules` in a rustwall config must be an array of tables");

    // Remove any existing copy of our rule wherever it is, then reinsert
    // at index 0 -- guarantees first-match-wins even if a human edited
    // the file (e.g. added a new `accept` rule at the top) between syncs.
    rules.retain(|r| r.get("name").and_then(|n| n.as_str()) != Some(CONFIRMED_MALICIOUS_RULE));

    let mut rule = toml::map::Map::new();
    rule.insert("name".to_string(), toml::Value::String(CONFIRMED_MALICIOUS_RULE.to_string()));
    rule.insert("protocol".to_string(), toml::Value::String("any".to_string()));
    rule.insert(
        "src".to_string(),
        toml::Value::String(format!("alias:{CONFIRMED_MALICIOUS_ALIAS}")),
    );
    rule.insert("action".to_string(), toml::Value::String("drop".to_string()));
    rule.insert("log".to_string(), toml::Value::Boolean(true));
    rules.insert(0, toml::Value::Table(rule));
}

/// Read-only helper for tests/tools that want to see the current
/// confirmed-malicious set without triggering a reload.
#[derive(Debug, Deserialize)]
struct AliasesOnly {
    #[serde(default)]
    aliases: Vec<AliasOnly>,
}

#[derive(Debug, Deserialize)]
struct AliasOnly {
    name: String,
    #[serde(default)]
    cidrs: Vec<String>,
}

pub fn current_confirmed_hosts(config_path: &Path) -> Result<Vec<String>, FirewallSyncError> {
    let text = fs::read_to_string(config_path).map_err(|source| FirewallSyncError::Read {
        path: config_path.to_path_buf(),
        source,
    })?;
    let parsed: AliasesOnly = toml::from_str(&text).map_err(|source| FirewallSyncError::Parse {
        path: config_path.to_path_buf(),
        source,
    })?;
    Ok(parsed
        .aliases
        .into_iter()
        .find(|a| a.name == CONFIRMED_MALICIOUS_ALIAS)
        .map(|a| a.cidrs)
        .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> &'static str {
        r#"
queue_num = 0
queue_workers = 2
default_policy = "drop"

[[aliases]]
name = "office"
cidrs = ["10.0.0.0/24"]

[[rules]]
name = "allow-office-ssh"
src = "alias:office"
dst_port = "22"
action = "accept"
"#
    }

    #[test]
    fn inserts_alias_and_rule_when_absent() {
        let mut doc: toml::Value = toml::from_str(sample_config()).unwrap();
        let hosts = ["203.0.113.9".parse().unwrap()];
        upsert_alias(&mut doc, &hosts);
        upsert_blocking_rule(&mut doc);

        let aliases = doc.get("aliases").unwrap().as_array().unwrap();
        assert!(aliases.iter().any(|a| a.get("name").unwrap().as_str() == Some(CONFIRMED_MALICIOUS_ALIAS)));

        let rules = doc.get("rules").unwrap().as_array().unwrap();
        assert_eq!(rules[0].get("name").unwrap().as_str(), Some(CONFIRMED_MALICIOUS_RULE));
        assert_eq!(rules[0].get("action").unwrap().as_str(), Some("drop"));
    }

    #[test]
    fn re_sync_replaces_cidrs_and_keeps_rule_first() {
        let mut doc: toml::Value = toml::from_str(sample_config()).unwrap();
        upsert_alias(&mut doc, &["203.0.113.9".parse().unwrap()]);
        upsert_blocking_rule(&mut doc);
        // A human (or another rule) adds something ahead of index 0.
        doc.get_mut("rules")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .insert(0, toml::from_str(r#"name="new-allow"
action="accept""#).unwrap());

        upsert_alias(&mut doc, &["203.0.113.9".parse().unwrap(), "198.51.100.4".parse().unwrap()]);
        upsert_blocking_rule(&mut doc);

        let rules = doc.get("rules").unwrap().as_array().unwrap();
        assert_eq!(rules[0].get("name").unwrap().as_str(), Some(CONFIRMED_MALICIOUS_RULE));

        let aliases = doc.get("aliases").unwrap().as_array().unwrap();
        let ours = aliases
            .iter()
            .find(|a| a.get("name").unwrap().as_str() == Some(CONFIRMED_MALICIOUS_ALIAS))
            .unwrap();
        let cidrs = ours.get("cidrs").unwrap().as_array().unwrap();
        assert_eq!(cidrs.len(), 2);
    }
}
