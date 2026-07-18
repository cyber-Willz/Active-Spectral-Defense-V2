// asd-log-ingester
//
// Decoupled sidecar (see schema.sql's header comment for why this is
// out-of-process rather than a Postgres write inside the orchestrator's
// correlation hot path). Tails the orchestrator's tracing output,
// extracts three known structured event shapes, writes them to
// Postgres, and -- for events worth a human's attention -- POSTs a
// compact JSON payload to an n8n webhook for alerting/ticketing.
//
// Usage:
//   ASD_PG_URL=postgres://asd:asd@localhost:5432/asd \
//   ASD_N8N_WEBHOOK=http://localhost:5678/webhook/asd-alerts \
//   node ingest.mjs /path/to/orchestrator.log

import { createReadStream, statSync, existsSync } from "node:fs";
import { createInterface } from "node:readline";
import pg from "pg";

const LOG_PATH = process.argv[2] ?? process.env.ASD_LOG_PATH;
const PG_URL = process.env.ASD_PG_URL ?? "postgres://asd:asd@localhost:5432/asd";
const N8N_WEBHOOK = process.env.ASD_N8N_WEBHOOK ?? "";
const POLL_MS = 1000;

if (!LOG_PATH) {
  console.error("usage: node ingest.mjs <orchestrator.log path> (or set ASD_LOG_PATH)");
  process.exit(1);
}

const pool = new pg.Pool({ connectionString: PG_URL });

const stripAnsi = (s) => s.replace(/\x1b\[[0-9;]*m/g, "");

// key=value tokenizer that tolerates a quoted value and a
// parenthesized value (tracing's Debug-format enums, e.g.
// disposition=QueuedForReview(LowConfidenceAttack)).
function parseKv(line) {
  const out = {};
  const re = /(\w+)=("(?:[^"\\]|\\.)*"|\([^)]*\)\S*|\S+)/g;
  let m;
  while ((m = re.exec(line))) {
    let v = m[2];
    if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
    out[m[1]] = v;
  }
  return out;
}

// Some components in this pipeline (rustwall) emit pure JSON log lines
// (`{"timestamp":"...","level":"INFO","fields":{"message":"...", ...}}`)
// instead of tracing's default pretty-print (`2026-...Z  INFO crate: msg
// key=value ...`). Normalize both into a common {ts, text} shape before
// running the line through the same key=value/substring matching below,
// rather than maintaining two parallel parsers.
function normalizeLine(rawLine) {
  const line = stripAnsi(rawLine);
  if (line.startsWith("{")) {
    try {
      const obj = JSON.parse(line);
      const msg = obj.fields?.message ?? "";
      const rest = Object.entries(obj.fields ?? {})
        .filter(([k]) => k !== "message")
        .map(([k, v]) => `${k}=${v}`)
        .join(" ");
      return { ts: obj.timestamp, text: `${msg} ${rest}`.trim(), raw: line };
    } catch {
      // fall through to treating it as a plain line
    }
  }
  return { ts: line.slice(0, 27), text: line, raw: line };
}

async function postWebhook(event) {
  if (!N8N_WEBHOOK) return;
  try {
    await fetch(N8N_WEBHOOK, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(event),
    });
  } catch (err) {
    console.error("n8n webhook post failed:", err.message);
  }
}

async function handleLine(rawLine) {
  const { ts, text: line, raw } = normalizeLine(rawLine);

  if (line.includes("verdict handled")) {
    const kv = parseKv(line);
    const disposition = kv.disposition ?? "unknown";
    const reasonMatch = disposition.match(/\(([^)]+)\)/);
    const reason = reasonMatch ? reasonMatch[1] : null;
    const confidence = parseFloat(kv.confidence ?? "0");

    await pool.query(
      `INSERT INTO verdicts (ts, host, disposition, reason, confidence, raw_line)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [ts, kv.host, disposition, reason, confidence, raw]
    );

    // Alert-worthy: anything not a routine low-confidence queue entry.
    if (disposition.startsWith("Contained") || confidence >= 0.9) {
      await postWebhook({
        type: "verdict",
        severity: disposition.startsWith("Contained") ? "critical" : "high",
        host: kv.host,
        disposition,
        confidence,
        ts,
      });
    }
    return;
  }

  if (line.includes("quarantined file path=")) {
    const kv = parseKv(line);
    await pool.query(
      `INSERT INTO quarantine_events (ts, file_path, signature, quarantine_id, raw_line)
       VALUES ($1, $2, $3, $4, $5)`,
      [ts, kv.path, kv.signature, kv.id, raw]
    );
    await postWebhook({
      type: "quarantine",
      severity: "high",
      path: kv.path,
      signature: kv.signature,
      ts,
    });
    return;
  }

  if (line.includes("SIGHUP: rules reloaded")) {
    const kv = parseKv(line);
    await pool.query(
      `INSERT INTO containment_events (ts, event_type, rule_count, raw_line)
       VALUES ($1, $2, $3, $4)`,
      [ts, "firewall_reload", parseInt(kv.rule_count ?? "0", 10), raw]
    );
    await postWebhook({
      type: "containment",
      severity: "critical",
      event: "firewall_reload",
      rule_count: kv.rule_count,
      ts,
    });
    return;
  }
}

// Simple polling tail -- avoids a native fs-watch dependency; fine for
// a log file being appended a few lines/sec.
async function tail(path) {
  let position = existsSync(path) ? 0 : 0; // start at 0: ingest full history on boot
  console.log(`asd-log-ingester: tailing ${path}`);
  console.log(`  postgres: ${PG_URL.replace(/:[^:@]*@/, ":***@")}`);
  console.log(`  n8n webhook: ${N8N_WEBHOOK || "(none configured)"}`);

  while (true) {
    if (existsSync(path)) {
      const size = statSync(path).size;
      if (size > position) {
        const stream = createReadStream(path, { start: position, end: size - 1 });
        const rl = createInterface({ input: stream, crlfDelay: Infinity });
        for await (const line of rl) {
          if (line.trim()) {
            try {
              await handleLine(line);
            } catch (err) {
              console.error("ingest error on line:", err.message);
            }
          }
        }
        position = size;
      } else if (size < position) {
        // log rotated/truncated
        position = 0;
      }
    }
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
}

tail(LOG_PATH).catch((err) => {
  console.error("fatal:", err);
  process.exit(1);
});
