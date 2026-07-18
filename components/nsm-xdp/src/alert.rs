//! Alert model and sink. Alerts are emitted as newline-delimited JSON
//! so they can be piped straight into `jq`, Filebeat, or a SIEM.

use serde::Serialize;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub ts_unix: u64,
    pub severity: Severity,
    pub detector: &'static str,
    pub message: String,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub extra: serde_json::Value,
}

impl Alert {
    pub fn new(
        severity: Severity,
        detector: &'static str,
        message: impl Into<String>,
        src_ip: Option<IpAddr>,
        dst_ip: Option<IpAddr>,
        extra: serde_json::Value,
    ) -> Self {
        Self {
            ts_unix: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            severity,
            detector,
            message: message.into(),
            src_ip,
            dst_ip,
            extra,
        }
    }

    pub fn emit(&self) {
        match serde_json::to_string(self) {
            Ok(line) => println!("{line}"),
            Err(e) => tracing::error!("failed to serialize alert: {e}"),
        }
    }
}
