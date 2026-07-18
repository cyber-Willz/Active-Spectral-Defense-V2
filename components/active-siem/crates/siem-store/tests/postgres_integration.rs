//! Integration tests against a real PostgreSQL instance. Requires
//! `SIEM_STORE_TEST_DATABASE_URL` (or the default below) to point at a
//! reachable database the test user can create tables in. These are
//! deliberately *not* mocked -- a persistence layer's whole job is talking
//! to the real database correctly (type mapping, transaction atomicity,
//! JSONB round-tripping), which a mock can't verify.
//!
//! Each test wipes the shared tables before running (`wipe_for_test`) and
//! uses distinct id ranges to avoid cross-test interference, since
//! `cargo test` runs tests in parallel threads by default.

use siem_core::{Alert, Event, EventKind, Severity};
use siem_store::Store;
use std::collections::HashMap;
use std::sync::Mutex;

fn test_db_url() -> String {
    std::env::var("SIEM_STORE_TEST_DATABASE_URL")
        .unwrap_or_else(|_| "host=127.0.0.1 user=siem password=siem dbname=active_siem".to_string())
}

fn connect() -> Store {
    let mut store = Store::connect(&test_db_url()).expect(
        "failed to connect to the test database -- set SIEM_STORE_TEST_DATABASE_URL, or run \
         against a local Postgres at host=127.0.0.1 user=siem password=siem dbname=active_siem",
    );
    store.migrate().expect("migration failed");
    store
}

// Postgres connections + table truncation don't compose safely across
// parallel test threads (one test's TRUNCATE can race another's INSERT),
// so serialize the whole suite with a single lock rather than requiring
// per-test isolated databases. Recovers from poison (`unwrap_or_else`
// rather than `unwrap`) rather than propagating it: if an earlier test in
// the suite panics (e.g. connection/auth failure), every later test
// should still get to run and report its own real result instead of
// masking a genuine failure behind nine identical, uninformative
// `PoisonError`s.
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn log_event(id: u64, host: &str, message: &str) -> Event {
    let mut fields = HashMap::new();
    fields.insert("severity".to_string(), "notice".to_string());
    Event {
        id,
        timestamp_ms: 1_700_000_000_000 + id,
        host: host.to_string(),
        agent_id: format!("agent-{host}"),
        kind: EventKind::Log {
            source: "sshd".to_string(),
            message: message.to_string(),
        },
        fields,
    }
}

fn flow_event(id: u64) -> Event {
    Event {
        id,
        timestamp_ms: 1_700_000_100_000 + id,
        host: "sensor-1".to_string(),
        agent_id: "agent-sensor-1".to_string(),
        kind: EventKind::Flow {
            src_ip: "198.51.100.77".to_string(),
            dst_ip: "203.0.113.9".to_string(),
            src_port: 51000,
            dst_port: 443,
            proto: 6,
            duration_ms: 900_000,
            bytes_src_to_dst: 40_000,
            bytes_dst_to_src: 900,
            packets: 210,
            flags: "SAP".to_string(),
        },
        fields: HashMap::new(),
    }
}

fn alert_with_sources(id: u64, severity: Severity, source_events: Vec<u64>) -> Alert {
    let mut context = HashMap::new();
    context.insert("mitre_tactic".to_string(), "TA0006".to_string());
    Alert {
        id,
        timestamp_ms: 1_700_000_200_000 + id,
        rule_id: "ssh-bruteforce".to_string(),
        title: "Repeated SSH authentication failures".to_string(),
        severity,
        mitre_technique: Some("T1110".to_string()),
        source_events,
        context,
    }
}

#[test]
fn event_round_trips_exactly_including_log_kind() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut store = connect();
    store.wipe_for_test().unwrap();

    let event = log_event(1, "web-01", "Failed password for root from 10.0.0.5");
    store.insert_event(&event).unwrap();

    let fetched = store.get_event(1).unwrap().expect("event should exist");
    assert_eq!(fetched.id, event.id);
    assert_eq!(fetched.timestamp_ms, event.timestamp_ms);
    assert_eq!(fetched.host, event.host);
    assert_eq!(fetched.agent_id, event.agent_id);
    assert_eq!(fetched.fields, event.fields);
    match fetched.kind {
        EventKind::Log { source, message } => {
            assert_eq!(source, "sshd");
            assert_eq!(message, "Failed password for root from 10.0.0.5");
        }
        other => panic!("expected Log kind, got {other:?}"),
    }
}

#[test]
fn flow_event_round_trips_exactly() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut store = connect();
    store.wipe_for_test().unwrap();

    let event = flow_event(2);
    store.insert_event(&event).unwrap();

    let fetched = store.get_event(2).unwrap().unwrap();
    match fetched.kind {
        EventKind::Flow {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto,
            duration_ms,
            bytes_src_to_dst,
            bytes_dst_to_src,
            packets,
            flags,
        } => {
            assert_eq!(src_ip, "198.51.100.77");
            assert_eq!(dst_ip, "203.0.113.9");
            assert_eq!(src_port, 51000);
            assert_eq!(dst_port, 443);
            assert_eq!(proto, 6);
            assert_eq!(duration_ms, 900_000);
            assert_eq!(bytes_src_to_dst, 40_000);
            assert_eq!(bytes_dst_to_src, 900);
            assert_eq!(packets, 210);
            assert_eq!(flags, "SAP");
        }
        other => panic!("expected Flow kind, got {other:?}"),
    }
}

#[test]
fn alert_round_trips_and_source_events_join_table_is_populated() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut store = connect();
    store.wipe_for_test().unwrap();

    store.insert_event(&log_event(10, "web-01", "auth failure 1")).unwrap();
    store.insert_event(&log_event(11, "web-01", "auth failure 2")).unwrap();
    let alert = alert_with_sources(100, Severity::High, vec![10, 11]);
    store.insert_alert(&alert).unwrap();

    let fetched = store.get_alert(100).unwrap().expect("alert should exist");
    assert_eq!(fetched.rule_id, "ssh-bruteforce");
    assert_eq!(fetched.severity, Severity::High);
    assert_eq!(fetched.mitre_technique.as_deref(), Some("T1110"));
    assert_eq!(fetched.source_events, vec![10, 11]);
    assert_eq!(fetched.context.get("mitre_tactic").map(String::as_str), Some("TA0006"));

    // The normalized join table, not just the JSONB array, must reflect
    // this -- this is the query the join table exists to serve.
    let mut events = store.events_for_alert(100).unwrap();
    events.sort_by_key(|e| e.id);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].id, 10);
    assert_eq!(events[1].id, 11);
}

#[test]
fn upsert_semantics_converge_rather_than_error() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut store = connect();
    store.wipe_for_test().unwrap();

    let mut event = log_event(20, "web-02", "first version");
    store.insert_event(&event).unwrap();
    event.kind = EventKind::Log {
        source: "sshd".to_string(),
        message: "corrected version".to_string(),
    };
    store.insert_event(&event).unwrap(); // re-insert with same id, changed content

    let fetched = store.get_event(20).unwrap().unwrap();
    match fetched.kind {
        EventKind::Log { message, .. } => assert_eq!(message, "corrected version"),
        other => panic!("expected Log kind, got {other:?}"),
    }
    assert_eq!(store.count_events().unwrap() >= 1, true);
}

#[test]
fn re_inserting_alert_replaces_join_rows_not_accumulates_them() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut store = connect();
    store.wipe_for_test().unwrap();

    store.insert_event(&log_event(30, "web-03", "e1")).unwrap();
    store.insert_event(&log_event(31, "web-03", "e2")).unwrap();
    store.insert_event(&log_event(32, "web-03", "e3")).unwrap();

    store.insert_alert(&alert_with_sources(200, Severity::Medium, vec![30, 31])).unwrap();
    // Re-insert the same alert id with a different source-events set --
    // the join table must reflect the new set exactly, not the union.
    store.insert_alert(&alert_with_sources(200, Severity::Medium, vec![32])).unwrap();

    let events = store.events_for_alert(200).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, 32);
}

#[test]
fn severity_filter_and_ordering() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut store = connect();
    store.wipe_for_test().unwrap();

    store.insert_alert(&alert_with_sources(300, Severity::Low, vec![])).unwrap();
    store.insert_alert(&alert_with_sources(301, Severity::Critical, vec![])).unwrap();
    store.insert_alert(&alert_with_sources(302, Severity::High, vec![])).unwrap();
    store.insert_alert(&alert_with_sources(303, Severity::Info, vec![])).unwrap();

    let high_plus = store.list_alerts_at_least(Severity::High, 10).unwrap();
    let ids: Vec<u64> = high_plus.iter().map(|a| a.id).collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&301));
    assert!(ids.contains(&302));

    let recent = store.list_recent_alerts(10).unwrap();
    // newest-first: id 303 has the highest timestamp_ms in this fixture set
    assert_eq!(recent.first().map(|a| a.id), Some(303));
}

#[test]
fn get_missing_event_and_alert_return_none_not_error() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut store = connect();
    store.wipe_for_test().unwrap();

    assert!(store.get_event(999_999).unwrap().is_none());
    assert!(store.get_alert(999_999).unwrap().is_none());
}

#[test]
fn counts_reflect_inserted_rows() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut store = connect();
    store.wipe_for_test().unwrap();

    store.insert_event(&log_event(40, "web-04", "e")).unwrap();
    store.insert_event(&log_event(41, "web-04", "e")).unwrap();
    store.insert_alert(&alert_with_sources(400, Severity::Low, vec![])).unwrap();

    assert_eq!(store.count_events().unwrap(), 2);
    assert_eq!(store.count_alerts().unwrap(), 1);
}

#[test]
fn migrate_is_idempotent() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut store = connect();
    // connect() already migrated once; migrating again must not error.
    store.migrate().unwrap();
    store.migrate().unwrap();
}
