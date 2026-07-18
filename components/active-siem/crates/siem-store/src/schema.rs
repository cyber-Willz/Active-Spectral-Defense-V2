//! Schema for `siem-core`'s `Event`/`Alert` data model.
//!
//! Design: `EventKind` (a 3-variant enum with different fields per variant
//! -- `Log`, `Flow`, `FileIntegrity`) is stored as `JSONB` rather than
//! normalized into per-kind columns or tables. A fully normalized schema
//! (either a table per kind, or a wide table with nullable columns for
//! every kind's fields) is the "more correct" relational design, but adds
//! real schema-migration overhead every time a variant's fields change,
//! for a benefit (SQL-native queries into flow-specific fields like
//! `dst_port`) this project doesn't yet need -- nothing here queries by
//! flow fields directly, `siem-ml` reads them from the in-process `Event`,
//! not from SQL. JSONB keeps the schema stable across `EventKind` changes
//! and is still indexable/queryable (`kind->>'src_ip'`, GIN indexes, etc.)
//! if that need shows up later. `fields` and `context` (both free-form
//! string bags by design in `siem-core`) get the same treatment for the
//! same reason.
//!
//! `alert_source_events` is a genuine normalized join table, kept
//! alongside `alerts.source_events` (which stays JSONB so `Alert` round-
//! trips exactly): "which alerts reference event X" is a real query this
//! schema is expected to answer efficiently, unlike the `EventKind`
//! internals above.
pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS events (
    id              BIGINT PRIMARY KEY,
    timestamp_ms    BIGINT NOT NULL,
    host            TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    kind_type       TEXT NOT NULL,
    kind            JSONB NOT NULL,
    fields          JSONB NOT NULL DEFAULT '{}'::jsonb,
    inserted_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp_ms ON events (timestamp_ms);
CREATE INDEX IF NOT EXISTS idx_events_host ON events (host);
CREATE INDEX IF NOT EXISTS idx_events_kind_type ON events (kind_type);

CREATE TABLE IF NOT EXISTS alerts (
    id                BIGINT PRIMARY KEY,
    timestamp_ms      BIGINT NOT NULL,
    rule_id           TEXT NOT NULL,
    title             TEXT NOT NULL,
    severity          SMALLINT NOT NULL,
    mitre_technique   TEXT,
    source_events     JSONB NOT NULL DEFAULT '[]'::jsonb,
    context           JSONB NOT NULL DEFAULT '{}'::jsonb,
    inserted_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp_ms ON alerts (timestamp_ms);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts (rule_id);

CREATE TABLE IF NOT EXISTS alert_source_events (
    alert_id  BIGINT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    event_id  BIGINT NOT NULL,
    PRIMARY KEY (alert_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_alert_source_events_event_id ON alert_source_events (event_id);
"#;
