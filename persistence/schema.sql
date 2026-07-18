-- active-spectral-defense persistence layer.
-- Decoupled from the orchestrator process on purpose: the correlation
-- engine's hot path (siem-correlation) must never block on a DB write
-- (its own doc comments say lane sends use try_send and drop under
-- load -- a synchronous Postgres write in that path would reintroduce
-- exactly the kind of stall it's designed to avoid). Ingestion happens
-- out-of-process, tailing the orchestrator's structured log output.

CREATE TABLE IF NOT EXISTS verdicts (
    id              BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
    host            INET NOT NULL,
    disposition     TEXT NOT NULL,       -- e.g. QueuedForReview(LowConfidenceAttack), Contained
    reason          TEXT,                -- extracted from disposition's inner variant, if present
    confidence      DOUBLE PRECISION NOT NULL,
    raw_line        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verdicts_ts ON verdicts (ts);
CREATE INDEX IF NOT EXISTS idx_verdicts_host ON verdicts (host);
CREATE INDEX IF NOT EXISTS idx_verdicts_disposition ON verdicts (disposition);

CREATE TABLE IF NOT EXISTS quarantine_events (
    id              BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
    file_path       TEXT NOT NULL,
    signature       TEXT NOT NULL,
    quarantine_id   TEXT NOT NULL,
    raw_line        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_quarantine_ts ON quarantine_events (ts);
CREATE INDEX IF NOT EXISTS idx_quarantine_signature ON quarantine_events (signature);

CREATE TABLE IF NOT EXISTS containment_events (
    id              BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_type      TEXT NOT NULL,        -- e.g. 'firewall_reload'
    rule_count      INTEGER,
    raw_line        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_containment_ts ON containment_events (ts);

-- Convenience view for a Power BI / dashboard "at a glance" panel.
CREATE OR REPLACE VIEW verdict_summary AS
SELECT
    date_trunc('minute', ts) AS minute,
    disposition,
    count(*) AS n,
    avg(confidence) AS avg_confidence
FROM verdicts
GROUP BY 1, 2
ORDER BY 1 DESC;
