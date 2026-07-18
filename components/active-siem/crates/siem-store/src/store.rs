//! `Store`: a thin, synchronous wrapper around `postgres::Client` that
//! persists `siem_core::Event`/`Alert`. Synchronous deliberately -- the
//! rest of this workspace (collector, rules, response) is plain blocking
//! Rust with no async runtime, and `postgres` (unlike `sqlx`/raw
//! `tokio-postgres`) gives a blocking API backed by its own internal
//! runtime, so this crate doesn't need to introduce `tokio` at every call
//! site just to persist an alert.
//!
//! # Why PostgreSQL specifically
//! Event/alert data here is inherently relational (an alert references N
//! source events; queries like "every High+ alert in the last hour" or
//! "every event behind alert X" are joins/filters, not key-value lookups),
//! needs ACID guarantees for an audit trail (a partially-written alert is
//! worse than a rejected one), and JSONB gives a clean way to store
//! `EventKind`'s per-variant fields and the free-form `fields`/`context`
//! bags without a rigid, migration-heavy schema (see `schema.rs`) while
//! remaining SQL-queryable if that need grows. A document store would lose
//! the relational query surface; SQLite would lose concurrent-writer
//! safety and network access for a real multi-agent deployment.

pub use crate::error::Result;

use crate::convert::{event_id_from_i64, event_id_to_i64, severity_from_i16, severity_to_i16};
use crate::schema;
use postgres::types::Json;
use postgres::{Client, NoTls, Row};
use siem_core::{Alert, Event, EventId, EventKind, Severity};
use std::collections::HashMap;

pub struct Store {
    client: Client,
}

impl Store {
    /// Connects with `postgres`'s standard connection-string format, e.g.
    /// `"host=localhost user=siem password=siem dbname=active_siem"` or
    /// `"postgres://siem:siem@localhost:5432/active_siem"`.
    ///
    /// Plaintext (`NoTls`) is fine for a local/trusted-network Postgres in
    /// this demo's scope; a production deployment talking to Postgres over
    /// an untrusted network should use `postgres-native-tls` or
    /// `postgres-openssl` instead and swap `NoTls` for a real connector --
    /// that's a connection-layer change only, nothing above `Store::connect`
    /// needs to know about it.
    pub fn connect(conninfo: &str) -> Result<Self> {
        let client = Client::connect(conninfo, NoTls)?;
        Ok(Self { client })
    }

    /// Idempotent: safe to call on every startup. `CREATE TABLE IF NOT
    /// EXISTS`/`CREATE INDEX IF NOT EXISTS` throughout `schema::SCHEMA`
    /// mean this never errors on an already-migrated database. There's no
    /// migration *versioning* here (no `schema_migrations` table, no
    /// up/down scripts) -- fine for one additive schema, not a substitute
    /// for a real migration tool (`sqlx-cli`, `refinery`) once this schema
    /// needs to evolve with existing data in it.
    pub fn migrate(&mut self) -> Result<()> {
        self.client.batch_execute(schema::SCHEMA)?;
        Ok(())
    }

    /// Upserts one event. `ON CONFLICT (id) DO UPDATE` rather than plain
    /// `INSERT` because re-ingesting the same event id (e.g. a collector
    /// retry after a network blip) should converge, not error.
    pub fn insert_event(&mut self, event: &Event) -> Result<()> {
        let id = event_id_to_i64(event.id)?;
        let kind_type = kind_type_str(&event.kind);
        let kind_json = serde_json::to_value(&event.kind)?;
        let fields_json = serde_json::to_value(&event.fields)?;

        self.client.execute(
            "INSERT INTO events (id, timestamp_ms, host, agent_id, kind_type, kind, fields)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (id) DO UPDATE SET
                timestamp_ms = EXCLUDED.timestamp_ms,
                host = EXCLUDED.host,
                agent_id = EXCLUDED.agent_id,
                kind_type = EXCLUDED.kind_type,
                kind = EXCLUDED.kind,
                fields = EXCLUDED.fields",
            &[
                &id,
                &(event.timestamp_ms as i64),
                &event.host,
                &event.agent_id,
                &kind_type,
                &Json(&kind_json),
                &Json(&fields_json),
            ],
        )?;
        Ok(())
    }

    /// Upserts one alert and its `alert_source_events` join rows, in a
    /// single transaction -- a real deployment must never observe an alert
    /// row with a stale or missing source-events join (either both commit
    /// or neither does).
    pub fn insert_alert(&mut self, alert: &Alert) -> Result<()> {
        let id = event_id_to_i64(alert.id)?;
        let source_event_ids: Vec<i64> = alert
            .source_events
            .iter()
            .map(|&e| event_id_to_i64(e))
            .collect::<Result<_>>()?;
        let source_events_json = serde_json::to_value(&alert.source_events)?;
        let context_json = serde_json::to_value(&alert.context)?;
        let severity = severity_to_i16(alert.severity);

        let mut tx = self.client.transaction()?;

        tx.execute(
            "INSERT INTO alerts (id, timestamp_ms, rule_id, title, severity, mitre_technique, source_events, context)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (id) DO UPDATE SET
                timestamp_ms = EXCLUDED.timestamp_ms,
                rule_id = EXCLUDED.rule_id,
                title = EXCLUDED.title,
                severity = EXCLUDED.severity,
                mitre_technique = EXCLUDED.mitre_technique,
                source_events = EXCLUDED.source_events,
                context = EXCLUDED.context",
            &[
                &id,
                &(alert.timestamp_ms as i64),
                &alert.rule_id,
                &alert.title,
                &severity,
                &alert.mitre_technique,
                &Json(&source_events_json),
                &Json(&context_json),
            ],
        )?;

        tx.execute("DELETE FROM alert_source_events WHERE alert_id = $1", &[&id])?;
        for event_id in &source_event_ids {
            tx.execute(
                "INSERT INTO alert_source_events (alert_id, event_id) VALUES ($1, $2)
                 ON CONFLICT DO NOTHING",
                &[&id, event_id],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn get_event(&mut self, id: EventId) -> Result<Option<Event>> {
        let id = event_id_to_i64(id)?;
        let row = self
            .client
            .query_opt("SELECT id, timestamp_ms, host, agent_id, kind, fields FROM events WHERE id = $1", &[&id])?;
        row.map(|r| row_to_event(&r)).transpose()
    }

    pub fn get_alert(&mut self, id: EventId) -> Result<Option<Alert>> {
        let id = event_id_to_i64(id)?;
        let row = self.client.query_opt(
            "SELECT id, timestamp_ms, rule_id, title, severity, mitre_technique, source_events, context
             FROM alerts WHERE id = $1",
            &[&id],
        )?;
        row.map(|r| row_to_alert(&r)).transpose()
    }

    /// Every event referenced by `alert_id`, via the normalized join table
    /// (not by unnesting `alerts.source_events`) -- this is the query the
    /// join table exists for.
    pub fn events_for_alert(&mut self, alert_id: EventId) -> Result<Vec<Event>> {
        let alert_id = event_id_to_i64(alert_id)?;
        let rows = self.client.query(
            "SELECT e.id, e.timestamp_ms, e.host, e.agent_id, e.kind, e.fields
             FROM events e
             JOIN alert_source_events j ON j.event_id = e.id
             WHERE j.alert_id = $1
             ORDER BY e.timestamp_ms ASC",
            &[&alert_id],
        )?;
        rows.iter().map(row_to_event).collect()
    }

    /// Most recent `limit` alerts, newest first.
    pub fn list_recent_alerts(&mut self, limit: i64) -> Result<Vec<Alert>> {
        let rows = self.client.query(
            "SELECT id, timestamp_ms, rule_id, title, severity, mitre_technique, source_events, context
             FROM alerts ORDER BY timestamp_ms DESC LIMIT $1",
            &[&limit],
        )?;
        rows.iter().map(row_to_alert).collect()
    }

    /// Alerts at or above `floor` severity, newest first -- the query a
    /// dashboard's "what needs attention" view would run.
    pub fn list_alerts_at_least(&mut self, floor: Severity, limit: i64) -> Result<Vec<Alert>> {
        let floor = severity_to_i16(floor);
        let rows = self.client.query(
            "SELECT id, timestamp_ms, rule_id, title, severity, mitre_technique, source_events, context
             FROM alerts WHERE severity >= $1 ORDER BY timestamp_ms DESC LIMIT $2",
            &[&floor, &limit],
        )?;
        rows.iter().map(row_to_alert).collect()
    }

    pub fn count_events(&mut self) -> Result<i64> {
        let row = self.client.query_one("SELECT count(*) FROM events", &[])?;
        Ok(row.get(0))
    }

    pub fn count_alerts(&mut self) -> Result<i64> {
        let row = self.client.query_one("SELECT count(*) FROM alerts", &[])?;
        Ok(row.get(0))
    }

    /// Drops every row from every table this crate manages. Test/demo-reset
    /// use only -- deliberately not exposed as anything resembling a
    /// production "clear the SIEM" operation.
    #[doc(hidden)]
    pub fn wipe_for_test(&mut self) -> Result<()> {
        self.client
            .batch_execute("TRUNCATE alert_source_events, alerts, events")?;
        Ok(())
    }
}

fn kind_type_str(kind: &EventKind) -> &'static str {
    match kind {
        EventKind::Log { .. } => "log",
        EventKind::Flow { .. } => "flow",
        EventKind::FileIntegrity { .. } => "file_integrity",
    }
}

fn row_to_event(row: &Row) -> Result<Event> {
    let id: i64 = row.get("id");
    let kind_json: serde_json::Value = row.get::<_, Json<serde_json::Value>>("kind").0;
    let fields_json: serde_json::Value = row.get::<_, Json<serde_json::Value>>("fields").0;
    Ok(Event {
        id: event_id_from_i64(id),
        timestamp_ms: row.get::<_, i64>("timestamp_ms") as u64,
        host: row.get("host"),
        agent_id: row.get("agent_id"),
        kind: serde_json::from_value(kind_json)?,
        fields: serde_json::from_value::<HashMap<String, String>>(fields_json)?,
    })
}

fn row_to_alert(row: &Row) -> Result<Alert> {
    let id: i64 = row.get("id");
    let severity_raw: i16 = row.get("severity");
    let source_events_json: serde_json::Value = row.get::<_, Json<serde_json::Value>>("source_events").0;
    let context_json: serde_json::Value = row.get::<_, Json<serde_json::Value>>("context").0;
    Ok(Alert {
        id: event_id_from_i64(id),
        timestamp_ms: row.get::<_, i64>("timestamp_ms") as u64,
        rule_id: row.get("rule_id"),
        title: row.get("title"),
        severity: severity_from_i16(severity_raw)?,
        mitre_technique: row.get("mitre_technique"),
        source_events: serde_json::from_value::<Vec<EventId>>(source_events_json)?,
        context: serde_json::from_value::<HashMap<String, String>>(context_json)?,
    })
}
