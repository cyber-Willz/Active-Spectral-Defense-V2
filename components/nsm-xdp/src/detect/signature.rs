//! Minimal Suricata/Snort-style content-match engine. Rules are plain
//! byte/string substrings matched against the first N bytes of the L4
//! payload -- enough to catch cleartext credential leaks, known
//! malicious user agents, and webshell-ish HTTP requests without
//! pulling in a full DPI/regex engine.

use crate::alert::{Alert, Severity};
use crate::packet::PacketMeta;

pub struct Rule {
    pub name: &'static str,
    pub pattern: &'static [u8],
    pub severity: Severity,
}

pub struct SignatureEngine {
    rules: Vec<Rule>,
}

impl SignatureEngine {
    pub fn with_default_ruleset() -> Self {
        Self {
            rules: vec![
                Rule { name: "cleartext-http-basic-auth", pattern: b"Authorization: Basic", severity: Severity::Medium },
                Rule { name: "ftp-cleartext-user", pattern: b"USER ", severity: Severity::Low },
                Rule { name: "suspicious-user-agent-curl", pattern: b"User-Agent: curl", severity: Severity::Info },
                Rule { name: "possible-webshell-cmd", pattern: b"cmd=", severity: Severity::Medium },
                Rule { name: "possible-sqli-union-select", pattern: b"UNION SELECT", severity: Severity::High },
                Rule { name: "possible-log4shell", pattern: b"${jndi:", severity: Severity::Critical },
                Rule { name: "eicar-test-string", pattern: b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE", severity: Severity::High },
            ],
        }
    }

    pub fn scan(&self, pkt: &PacketMeta) -> Vec<Alert> {
        if pkt.payload_head.is_empty() {
            return Vec::new();
        }
        let mut hits = Vec::new();
        for rule in &self.rules {
            if contains(&pkt.payload_head, rule.pattern) {
                hits.push(Alert::new(
                    rule.severity,
                    "signature",
                    format!("payload matched rule '{}' ({} -> {})", rule.name, pkt.src_ip, pkt.dst_ip),
                    Some(pkt.src_ip),
                    Some(pkt.dst_ip),
                    serde_json::json!({ "rule": rule.name }),
                ));
            }
        }
        hits
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
