# ActiveSIEM

A minimal, working Rust SIEM skeleton: rule/threshold correlation (Wazuh/OSSEC-style)
fused with a burn.rs autoencoder for the class of attacks signature engines
structurally can't see - **low-and-slow infiltration** - and a fan-in
correlation engine (`siem-correlation`) that escalates to containment only
once evidence corroborates across independent detection lanes, or one lane
is already unambiguous (see `docs/architecture.svg`). Guarded, human-reviewed
active response closes the loop instead of just alerting, with optional
outbound webhook notifications (`siem-notify`, n8n-compatible) for the
humans actually doing the reviewing.

Builds and passes its full test suite on stock **Rust 1.75** (see "MSRV pins" below).

```
cargo test --workspace
cargo run -p siem-server        # runs the end-to-end demo
```

## What Wazuh, OSSEC, and Security Onion actually do

| | OSSEC | Wazuh | Security Onion |
|---|---|---|---|
| Core model | Agent tails logs -> decoder extracts fields -> rule tree matches, with `frequency`/`timeframe` threshold rules | OSSEC's architecture, forked and extended: same decoder/rule engine, plus FIM, vulnerability detection, and a REST API/indexer (OpenSearch) on top | Not agent-based - a sensor stack (Zeek + Suricata + Wazuh optionally) feeding Elastic/OpenSearch, oriented around Sigma rules and full-packet capture (Stenographer) for retrospective hunting |
| Detects well | Auth failures, known bad log patterns, file integrity changes, rootkit signatures | Everything OSSEC does, plus CVE-matched vulnerable software, compliance (PCI/HIPAA) mappings | Network-level reconnaissance, known-exploit signatures (Suricata/ET rules), protocol anomalies Zeek flags structurally |
| Structurally misses | Anything that doesn't cross a static threshold or match a signature - by design, these are rule engines | Same limitation - Wazuh is OSSEC's architecture, not a different detection paradigm | Passive/detection-only. No active response. Also signature/threshold-first - Sigma rules are declarative pattern matching, same category as OSSEC's rule tree |
| Active response | Yes - `active-response` scripts (e.g. `firewall-drop.sh`) fire on matching alerts | Yes - same mechanism, plus orchestration via the manager | No - explicitly out of scope; it's a monitoring/hunting platform |

The common gap across all three: they are **signature and threshold engines**.
That's exactly why "Infiltration" is the hardest class in datasets like
CIC-IDS2018 - a slow foothold making small, evenly-paced connections is
designed to stay under every static threshold and match no known signature.
Catching it needs a *learned model of what normal traffic looks like*, which
none of the three provide out of the box (Security Onion can bolt on ML via
its stack, but nothing ships by default).

## What this project does about it

Two detection layers, doing different jobs, feeding one alert stream:

1. **`siem-rules`** - a Sigma/OSSEC-lite correlation engine (YAML rules,
   sliding-window thresholds). Catches the *noisy* precursors to infiltration:
   brute force, vertical port scans. This is what Wazuh/OSSEC/Security Onion
   already do well, reimplemented small enough to read in one sitting.

2. **`siem-ml`** - a burn.rs autoencoder trained only on benign flow features
   (duration, byte ratios, packet counts). Reconstruction error above a
   calibrated threshold flags the flow as anomalous. This is the layer that
   catches what the other three miss: a connection that matches no signature
   and never crosses a count threshold, but doesn't *look* like the rest of
   the traffic on the network.

3. **`siem-response`** - unlike Security Onion (no active response at all),
   this closes the loop, but with an explicit fail-to-escalate policy
   (severity floor, allowlist, rate limit, auto-expiring blocks) rather than
   Wazuh/OSSEC's fire-and-forget script model - a bad automated block is a
   self-inflicted outage, so the default posture is "escalate to a human"
   unless every guard passes.

```
crates/
  siem-core                event/alert data model
  siem-collector           log tailing + decoders (agent side)
  siem-rules               YAML threshold/correlation rules
  siem-ml                  burn.rs autoencoder + supervised classifier for flow scoring
  siem-response             guarded active response (severity/allowlist/rate-limit)
  siem-review               human-in-the-loop review gate in front of siem-response
  siem-correlation          fan-in correlation engine (XDP/ClamAV/spectral lanes -> verdict)
  siem-correlation-bridge   wires siem-rules/siem-ml onto the correlation lanes and verdicts onto siem-review
  siem-store                PostgreSQL persistence for the Event/Alert data model
  siem-notify               outbound webhook notifications (n8n-compatible)
  siem-server               wires it all together (see main.rs for the demo)
  ontology-engine           in-memory knowledge-graph engine (audit trail backing store)
  review-queue              the review queue itself, backed by ontology-engine
```

`docs/architecture.svg` is the fan-in diagram this crate layout implements:
network telemetry through an NSM fast path (XDP enforcement lane), file/mail
through a ClamAV-style scan (quarantine lane), and flow telemetry through a
spectral/anomaly-scoring lane, all converging on the correlation engine
before any containment action executes.

## Demo output

```
=== ActiveSIEM demo ===

-- Connected to PostgreSQL, events/alerts will be persisted --
-- Outbound notifications disabled (set N8N_WEBHOOK_URL to enable) --

-- Simulating SSH brute force from 10.0.0.5 --
  ALERT [ssh-bruteforce] Repeated SSH authentication failures from one source (severity High, mitre Some("T1110"))

-- Training autoencoder on benign traffic shape --
  calibrated anomaly threshold: 0.00171

-- Scoring a suspected infiltration beacon (long, tiny, periodic, upload-heavy) --
  reconstruction error: 10.01863 (threshold 0.00171)
  flagged as anomalous/infiltration-like: true

-- Guarded, review-gated active response --
  review queue state: review_queue_state.json (0 existing item(s))

  3a. Confident classification (DenialOfService, 1.000):
[response:dry-run] would block 203.0.113.44 for alert 'Classifier: DenialOfService' (severity High)
      disposition: Executed

  3b. Borderline classification (Infiltration, 0.856 -- the exact confidence siem-ml/tests/categorical_isolation.rs measures as this classifier's one error):
      disposition: QueuedForReview(NovelPattern)  (no action taken)
      containment check before review: not approved
      -- analyst_priya reviews flow-beacon-1784202269129, confirms via pcap --
[response:dry-run] would block 198.51.100.77 for alert 'Classifier: Infiltration' (severity High)
      disposition after review: Executed
      containment check after review:  approved (decision dec-flow-beacon-1784202269129-1)
      full audit trail for flow-beacon-1784202269129: 1 decision(s) on the ontology graph

-- Correlation engine (fan-in across detection lanes) --
  4a. 10.0.0.5 -- verdict: Critical, confidence 1.00, reason SingleLaneCritical
      disposition: QueuedForReview(NovelPattern)
      -- analyst_priya reviews corr-10.0.0.5-1784202269134, confirms the rule engine wasn't a false positive --
[response:dry-run] would block 10.0.0.5 for alert 'Repeated SSH authentication failures from one source' (severity High)
      disposition after review: Executed
  4b. 10.0.0.20 -- verdict: High, confidence 0.93, reason MultiLaneCorroboration, sources [Spectral, ClamAv]
[response:dry-run] would block 10.0.0.20 for alert 'Multi-lane corroborated: anomalous beacon + AV hit on same host' (severity Critical)
      disposition: Executed
      (two corroborating lanes already cleared the confidence floor -- no human review needed here)
  correlation metrics: events_received=3 verdicts_emitted=2 verdicts_dropped=0

-- SLA sweep (fail-safe timeout path) --
  'flow-unreviewed-1784202269139' resolved via SLA fallback: verdict=dismiss (never auto-contains under fail-safe)
  (1 of these alerts went to tracing logs only -- set N8N_WEBHOOK_URL to route them out)

  review queue state saved to review_queue_state.json (persists across runs)
  PostgreSQL now holds 6 event(s) and 4 alert(s) (persists across runs)
```

The brute force is 5 identical log lines - a plain threshold rule gets it,
same as OSSEC would. The beacon is a single, ordinary-looking TCP flow; no
rule fires on it, but its reconstruction error is ~6000x the calibrated
benign threshold, so the ML layer catches what the rule layer structurally can't.

The two response cases (3a/3b) show why the review gate matters: 3a is
confidently classified and clears automatically, same as the old
direct-to-`ResponsePolicy` behavior. 3b uses **the exact 0.856 confidence
`siem-ml/tests/categorical_isolation.rs` measures as this classifier's one
real error** - the old code path would have auto-blocked `198.51.100.77` on
a call the classifier itself isn't reliably right about. With the gate in
place, nothing executes until a human (`analyst_priya`, standing in for a
real reviewer) records a decision - and that decision is now a permanent,
queryable node on the audit graph, not a printed string. Both layers of
persistence are real: run the binary twice in a row and the second run
reports the flow(s) queued by the first as already present in
`review_queue_state.json`, and `PostgreSQL now holds ...` reflects rows
that survive the process exiting, not just the current run's counters.
Running without a reachable Postgres degrades to a clear `WARNING` and
continues in-memory-only, rather than aborting the demo.

Part 4 is the correlation engine (see below): 4a reuses the *same real
bruteforce alert* from part 1, submitted through the XDP lane -- a single
lane, but one already backed by hard, confirmed thresholds, so the engine
emits a verdict off it alone (`SingleLaneCritical`). 4b corroborates the
*same real ML anomaly score* from part 2 with a simulated ClamAV hit on the
same internal host (`10.0.0.20`) -- two independently weaker signals that
together clear the review floor on their own, without a human, once fused
(`MultiLaneCorroboration`, confidence 0.93). Note that even the
already-Critical, already-`human_approved` XDP submission in 4a still goes
through a *second*, independent human review before executing -- see the
"Correlation engine" section below for why a single lane's own critical
call is deliberately not trusted as much as two lanes agreeing.

Part 5 (see "Would n8n improve this?" below) ingests one deliberately-
unreviewed flow and sweeps it immediately to show the fail-safe SLA path's
alert sink actually firing, live, not just in `review-queue`'s own test
suite. With `N8N_WEBHOOK_URL` unset (the default above), it says so and
logs instead; set it and every `QueuedForReview` disposition, every
correlation verdict, and this SLA breach all fire a real webhook POST -
verified against a real local receiver capturing all 5 deliveries in one
run, not simulated.

## Persistence (`siem-store`, PostgreSQL)

Previously there was no persistence layer at all: every `Event`/`Alert`
lived only in the demo process's memory for the duration of one run.
`siem-store` adds a real PostgreSQL-backed store for `siem-core`'s data
model (see `crates/siem-store/src/schema.rs` for the actual embedded DDL,
run automatically by `Store::migrate` on every startup).

**Why PostgreSQL specifically, not SQLite/MongoDB/a flat file:** event/alert
data here is inherently relational (an alert references N source events;
"every High+ alert in the last hour" or "every event behind alert X" are
joins/filters, not key-value lookups); a security audit trail needs ACID
guarantees (a partially-written alert is worse than a rejected one, and a
multi-agent SIEM has concurrent writers SQLite handles poorly); and
Postgres's `JSONB` gives a clean way to store `EventKind`'s three
differently-shaped variants and the free-form `fields`/`context` bags
without a rigid, migration-heavy schema, while remaining indexable/
queryable if a need to query into those fields directly shows up later.

**Schema shape** (`crates/siem-store/src/schema.rs`): `events` and `alerts`
tables with `JSONB` columns for `kind`/`fields`/`context`/`source_events`,
plus a genuinely normalized `alert_source_events` join table alongside the
JSONB array - "which alerts reference event X" is a real query this schema
answers via an index, not by unnesting JSON. `Store` (in
`crates/siem-store/src/store.rs`) wraps `postgres::Client` (the *blocking*
API `postgres` provides over `tokio-postgres`, chosen deliberately since
the rest of this workspace - collector, rules, response - is plain
synchronous Rust with no async runtime; introducing `tokio` at every call
site just to persist an alert would be a much bigger, unrelated change).
Inserts are upserts (`ON CONFLICT (id) DO UPDATE`): re-ingesting the same
event/alert id (a collector retry after a network blip) converges instead
of erroring, and `insert_alert` writes the alert row and its join rows in
one transaction, so an audit-trail reader never observes one without the
other.

`siem-server`'s demo binary wires this in end-to-end (see `main.rs`):
connects via `DATABASE_URL` (default
`host=127.0.0.1 user=siem password=siem dbname=active_siem`) at startup,
runs `migrate()`, and persists every event/alert as it's generated. If the
connection or migration fails, it prints one clear warning and continues
running the rest of the demo in-memory-only - a SIEM's detection/response
pipeline degrading gracefully when its persistence backend is briefly
unreachable, rather than refusing to run at all, mirrors the same
fail-open-on-infra posture `review_queue`'s SLA fail-safe policy already
takes on decisions (see above); a real deployment would additionally alert
loudly on this rather than just printing, which is out of scope for a demo
binary.

**The other half of "no persistence layer" was `review_queue`'s own state**:
its JSON-file persistence (`review_queue::store`) already existed and was
already tested, but wasn't wired into this demo binary, which built a
fresh in-memory `ReviewQueue` on every run - anything queued for review
vanished the moment the process exited. `main.rs` now loads/saves it via
`REVIEW_QUEUE_STATE_PATH` (default `review_queue_state.json`), so a flow
queued in one run is still pending review the next time the binary starts.
`ReviewGatedResponse`'s `queue`/`policy` fields are `pub` specifically so a
caller can do this without a bespoke persistence API duplicated in
`siem-review`.

**Setup**, if you want to run this locally:

```bash
sudo apt-get install postgresql
sudo -u postgres psql -c "CREATE ROLE siem WITH LOGIN PASSWORD 'siem' SUPERUSER;"
sudo -u postgres psql -c "CREATE DATABASE active_siem OWNER siem;"
cargo run -p siem-server   # connects, migrates, and persists automatically
```

`crates/siem-store/tests/postgres_integration.rs` runs 9 tests against a
real local Postgres (`SIEM_STORE_TEST_DATABASE_URL` to override the
connection string) - round-trips for both `EventKind` variants, upsert
convergence, join-table correctness on re-insert, severity filtering, and
migration idempotency. These aren't mocked: a persistence layer's whole job
is talking to the real database correctly (type mapping, transaction
atomicity, `JSONB` round-tripping), which a mock can't verify.

**What this doesn't do yet** (see "Honest gaps" below): connection
pooling (one `Client`, not a pool - fine for a single-process demo, wrong
for a real multi-agent server handling concurrent writes), a real migration
*versioning* tool (schema.rs's `CREATE TABLE IF NOT EXISTS` is additive-only,
fine for one schema, not a substitute for `sqlx-cli`/`refinery` once this
needs to evolve against existing data), and no `review_queue` audit-graph
data in Postgres - the two persistence layers are separate on purpose (see
above), which means a query spanning "this alert AND its full review
history" currently means querying two different stores, not one `JOIN`.

## Human-in-the-loop review gate (`siem-review`, `review-queue`, `ontology-engine`)

Added after analyzing `review_queue.tar.gz` (a companion project in this
workspace's ecosystem, built specifically to gate the 0.856-confidence
misclassification this crate's own classifier test suite documents). It
closes two gaps this README previously listed under "Honest gaps":

1. **No confidence-threshold/fallback wiring between the classifier and the
   autoencoder.** `siem_review::to_flow_prediction` takes the autoencoder's
   independent anomaly verdict (`siem_ml::is_anomalous`) as an input
   alongside the classifier's `Prediction`, and folds it into
   `review_queue`'s out-of-distribution signal - so a flow the autoencoder
   flags as unlike anything trained on is routed to a human even if the
   classifier itself sounds confident. This is exactly the fallback wiring
   this README previously flagged as missing (see the demo's 3b case,
   which is flagged `NovelPattern` because both signals disagree with
   "safe to auto-act," not just the classifier's raw confidence).

2. **`ResponsePolicy` had no actual human-review path.** Its guards
   (severity floor, allowlist, rate limit, dedup) decide whether to act
   *automatically*; anything that failed a guard was previously just an
   `Err(&'static str)` the demo binary printed and dropped - "escalate to
   human review" wasn't a real mechanism. `siem_review::ReviewGatedResponse`
   puts `review_queue::ReviewQueue` in front of `ResponsePolicy`: a
   prediction must clear the review trigger (confident, unambiguous,
   in-distribution) or be explicitly approved by a human via
   `resolve_and_execute` before `ResponsePolicy` - and therefore any
   `ResponseAction` - is ever reached. `ResponsePolicy` itself is untouched;
   the two compose rather than one replacing the other, so the existing
   allowlist/rate-limit/severity tests still hold (and still apply *after*
   review clears - see `siem-review`'s
   `review_approval_still_subject_to_allowlist_guard` test, which confirms
   a human "contain" verdict still can't block an allowlisted host).

Every decision - automatic or human, approve or dismiss - is recorded as an
`AuditDecision` node on an `ontology_engine::OntologyEngine` graph, linked
back to the `FlowPrediction` it decided. `ContainmentExecutor` (inside
`review-queue`) only ever authorizes action by walking that graph, never by
trusting a cached boolean - so an approval can be independently verified.
SLA timeouts default to **fail-safe** (dismiss, never auto-contain an
unreviewed call) and fire a loud `tracing::error!` alert via
`review_queue::alert::LoggingAlertSink` when a non-benign prediction times
out unreviewed, since that's the case where a real attack could otherwise
sit unactioned and unnoticed.

`review-queue` also ships its own CLI for driving review out-of-band from
the demo binary:

```
cargo run -p review_queue -- ingest --flow-id f1 --label Infiltration --confidence 0.856
cargo run -p review_queue -- list
cargo run -p review_queue -- review --flow-id f1 --reviewer analyst_priya --verdict contain --rationale "confirmed via pcap"
cargo run -p review_queue -- check --flow-id f1
```

Test coverage added: `siem-review`'s 6 tests cover the confident-auto-clear
case, the exact 0.856 case (queued, not executed), the autoencoder-driven
fallback trigger, human approval executing containment, the
allowlist-after-approval interaction, and fail-safe SLA timeout - on top of
`review-queue`'s own 17 tests (including a property test sweeping every
label/confidence combination to confirm fail-safe can never auto-contain)
and `ontology-engine`'s 17 graph-invariant tests. `cargo test --workspace`
runs all of it.

## Correlation engine (`siem-correlation`, `siem-correlation-bridge`)

Everything above this point gates *single-source* evidence: one classifier
call, one autoencoder score. `docs/architecture.svg` describes a different
shape - three independent detection lanes (an XDP-enforced NSM fast path,
a ClamAV-style file/mail scan, a spectral/anomaly-scoring engine) fanning
in to a correlation engine that only escalates to containment once evidence
actually corroborates across lanes, or one lane is already unambiguous.
`siem-correlation` implements exactly that fan-in engine; `siem-correlation-bridge`
wires it to what this codebase actually has.

**`siem-correlation` is deliberately standalone** - no dependency on
`siem-core` or anything else in this workspace (see its own crate docs for
the full rationale). That's a real design choice, not an integration
shortcut: a fan-in correlation engine is reusable infrastructure
independent of any one SIEM's event schema. Concretely:

- Three typed, non-blocking senders (`XdpSender`, `ClamAvSender`,
  `SpectralSender`) feed a single `tokio::sync::mpsc` consumer -
  `try_send`, never blocking, so a lane backpressuring the correlation
  engine can never stall XDP/ClamAV/the spectral engine themselves
  (dropped events are counted in `CorrelationMetrics`, not silently lost).
- Evidence is joined per-host (`IpAddr`), within a rolling window
  (`CorrelationConfig::window`, default 60s), with bounded memory even
  under an attacker fanning out across many source IPs (`max_evidence_per_host`,
  `max_tracked_hosts`, oldest-first eviction).
- **Emission rule:** a `CorrelationVerdict` fires the moment two *distinct*
  lanes corroborate the same host (`CorrelationReason::MultiLaneCorroboration`),
  or immediately for one lane's own `Critical`-severity event
  (`CorrelationReason::SingleLaneCritical`). A host with only one
  sub-critical lane by the time its window expires is never escalated -
  insufficient evidence, logged not acted on.

**What `siem-correlation-bridge` actually wires up** - and, just as
importantly, what it honestly doesn't:

- `siem-rules`' fast-path, threshold-based detections (SSH brute force,
  etc.) -> `XdpSender`. Not literally an XDP program; the mapping is that
  both are fast, signature/rate-shaped, network-level signals. The lane's
  `human_approved` flag corresponds to whether `review-queue` has already
  recorded a confirming decision.
- `siem-ml`'s autoencoder reconstruction error (normalized) or classifier
  confidence -> `SpectralSender`. This SIEM has no real spectral-graph
  computation (no Laplacian, no Fiedler vector); `fiedler_shift` is passed
  as `0.0` and documented as such, not synthesized to look plausible.
- **`ClamAvSender` has no real detector behind it in this codebase.**
  There is no file-scanning/AV component here. It's left fully wired and
  available - `siem-server`'s demo (part 4b) submits one event through it
  clearly labeled `SIMULATED.Win.Dropper.Generic (no real AV integration
  in this codebase)`, standing in for what a real ClamAV integration would
  submit, not presented as a genuine detection.
- `CorrelationVerdict` -> `review_queue::types::FlowPrediction` via
  `verdict_to_flow_prediction`, then through the *same*
  `ReviewGatedResponse` gate parts 3a/3b already use (`siem-review` was
  refactored to expose `handle_flow_prediction` as the shared core both
  the classifier path and the correlation path call into, rather than
  duplicating the gating logic). Critically, this means correlation output
  is **not** trusted more than a single classifier call just because two
  lanes already agree: `SingleLaneCritical` verdicts are deliberately
  routed through the same force-review path as autoencoder-flagged novelty
  (`is_out_of_distribution: true`) even at full confidence, since one
  lane's own critical call is weaker evidence than two independent lanes
  corroborating - see the demo's 4a, where an already-`human_approved` XDP
  submission still goes through a second, independent review before
  executing. A genuinely two-lane-corroborated verdict, in contrast, can
  clear `ReviewTrigger`'s confidence floor on its own (demo's 4b) - defense
  in depth in both directions, not just one.

Test coverage: `siem-correlation`'s own 5 tests (ported from the original
design, covering multi-lane corroboration, single-critical emission,
window expiry, backpressure, and per-host eviction under load) plus
`siem-correlation-bridge`'s 8 (`FlowKey`/`Protocol` conversion, both
`CorrelationReason` cases mapped correctly, and two full end-to-end
integration tests running a real `CorrelationEngine` on a real `tokio`
runtime through to a real `ReviewGatedResponse` decision - not mocked at
any stage).

`siem-correlation` is the first `tokio`-based crate in this otherwise
synchronous workspace. `siem-server`'s demo wraps just the correlation
section in `tokio::runtime::Runtime::new().block_on(...)`, keeping
everything else in `main()` plain synchronous Rust - deliberately, so
adding one async component didn't force converting the whole pipeline. One
real bug this surfaced during integration, worth noting since it's an easy
trap: `siem-store`'s `postgres::Client` is a *blocking* API that drives its
own connection with an internal `tokio` runtime, so calling it from
*inside* the demo's `block_on`'d async block panics ("Cannot start a
runtime from within a runtime"). The fix is structural, not a workaround -
the correlation section's async block returns the alert it built, and
`Store::insert_alert` is called after `block_on` returns, back in
synchronous context.

## Would n8n improve this? (`siem-notify`)

Asked and answered honestly rather than just implemented on request: **yes,
for one specific layer, and no for everything else.**

**Where it helps:** the *outbound notification* layer. `review_queue::alert::LoggingAlertSink`
already said this out loud before n8n came up at all - it "guarantees
something lands in logs; it does not page anyone. Production deployments
should wrap or replace this with a sink that actually reaches an on-call
human." Fanning one event out to Slack, email, PagerDuty, a ticket queue,
etc. is exactly what n8n (or any low-code workflow tool) is built for, and
doing it there means not hand-writing and maintaining a bespoke Rust HTTP
client for every downstream service this project might ever want to notify.

**Where it would hurt:** anywhere in the actual detection/correlation/
containment-decision pipeline. That logic needs to stay fast,
deterministic, and covered by the property/invariant tests this workspace
already leans on throughout (`sla_fail_safe_never_auto_contains_property`,
the containment-audit-graph invariants). Routing flow/event data through an
external low-code workflow engine *before* a containment decision would
add latency, a new failure mode, and a real security concern - SIEM
telemetry now flowing to a third-party-ish workflow runner - for none of
that rigor in return. n8n itself is also new attack surface: a real server
to run, patch, and secure. Notifications-only is the right blast radius for
that risk - if it's compromised, an attacker gets to see (or suppress)
notifications, never containment authority, since `siem-notify` has none.

**What's implemented:** `siem-notify` - a generic webhook client (`WebhookNotifier`),
deliberately not n8n-specific in wire format (any JSON-webhook receiver
works; n8n's "Webhook" trigger node just happens to be a natural target).
`WebhookAlertSink` adapts it to the `SlaBreachAlertSink` trait
`review_queue` already exposed for exactly this. `notify_queued_for_review`
and `notify_correlation_verdict` are called explicitly at each point in
`siem-server`'s demo where a flow gets queued or the correlation engine
emits a verdict - not baked into `review-queue`/`siem-review`'s core, so a
notification failure can never be able to affect either crate, and those
crates stay dependency-light. Entirely opt-in via `N8N_WEBHOOK_URL`; unset
is the normal case (unlike Postgres, no warning - just a one-line note).

```bash
N8N_WEBHOOK_URL="https://your-n8n-instance/webhook/xyz" cargo run -p siem-server
```

**A real bug this surfaced, fixed properly rather than worked around:**
`ReviewQueue::sweep_expired_with_sink` used to call `alert_sink.notify()`
*while still holding its internal lock*. Harmless with `LoggingAlertSink`
(a `tracing` call is effectively instant), but once a sink can do real
network I/O, a slow or unreachable webhook would have stalled every other
`ReviewQueue` operation (`ingest`, `record_decision`, ...) on any other
thread for up to the sink's timeout, once per breach in the sweep.
Refactored so all engine/state mutation happens under the lock, evidence is
collected, the lock is released, and *then* the alert sink is called -
`WebhookNotifier`'s own 3-second timeout now only bounds its own call, not
the rest of the system.

**Verified for real, not just compiled:** `siem-notify`'s tests run a real
minimal HTTP/1.1 server (plain `std::net::TcpListener`, no extra
dependency) that captures the actual POST body over a real socket - the
same wire contract (POST, JSON body) n8n's Webhook node expects, verified
honestly since a full n8n install wasn't feasible in this sandbox (`npm
install -g n8n` pulls a dependency from outside the network's allowed
domains). Beyond the crate's own tests, the full demo was run twice more
end to end against a real local webhook receiver: once confirming
`N8N_WEBHOOK_URL` unset correctly logs and skips network calls, once with
it set, capturing all 5 real deliveries the demo's 5 notification points
produce (two `queued_for_review`, two `correlation_verdict`, one
`sla_breach`) - not simulated, an actual second process receiving actual
HTTP requests.

## MSRV pins (Rust 1.75)

burn 0.13's dependency tree assumes a newer toolchain by default. Every pin
below is `cargo update -p <pkg>@<from> --precise <to>`, kept at the newest
version that still satisfies both the workspace's semver requirements and
rustc 1.75:

- `indexmap` -> 2.2.6 (2.14 requires edition2024)
- `rmp-serde` -> 1.1.2, `rmp` -> 0.8.14 (newer needs edition2024)
- `uuid` -> 1.10.0 (1.23 needs rustc 1.85)
- `rayon` -> 1.10.0, `rayon-core` -> 1.12.1 (newer needs rustc 1.80)
- `burn`/`burn-core` -> 0.13.0 (0.13.1+ pulls a `bincode` range needing rustc 1.85)
- `half` -> 2.4.1 (2.5+ needs rustc 1.81)
- `bincode` -> 2.0.0-rc.3 (burn-core's own required range; final 2.0.0 needs rustc 1.85)

`siem-store`'s Postgres driver stack (`postgres`/`tokio-postgres`/
`postgres-types`/`postgres-protocol`) needed the same treatment -- current
releases pull `hmac` 0.13 -> `digest` 0.11 -> `ctutils` -> `cmov` 0.5.4,
and separately `postgres-derive` 0.4.9, both of which require Cargo's
`edition2024` feature (unstable on 1.75). Pinned as a mutually-compatible
set, most-downstream first:

- `postgres` -> 0.19.9, `tokio-postgres` -> 0.7.12, `postgres-types` ->
  0.2.8, `postgres-protocol` -> 0.6.7, `postgres-derive` -> 0.4.6, `hmac`
  -> 0.12.1 (this whole chain resolves to `digest` 0.10.x /
  `getrandom` 0.2.x / `rand` 0.8.x, none of which need edition2024)

`siem-notify`'s `ureq` (with the `tls`/`json` features, for the webhook
client) hit the same wall a third time via a different path -
`idna_adapter` 1.2.2 (part of `url`'s Unicode/IDNA handling) and `zeroize`
1.9.0 both require edition2024:

- `idna_adapter` -> 1.1.0 (removes the whole `icu_*`/`zerotrie`/`yoke`
  chain those newer releases pulled in), `zeroize` -> 1.8.2

If you have a newer toolchain available, `cargo update` without `--precise`
pins will likely just work and pull current versions instead.

## Validated against real data - including a critical negative result

`crates/siem-ml/tests/infiltration_dataset.rs` runs three tests against real
CIC-IDS2018-style data, not just the synthetic beacon in the demo binary:

1. **50 real Infiltration flows** (RDP/SMB/HTTP low-and-slow traffic:
   `13.58.225.34` probing `172.31.69.13/24/25`, then `172.31.69.13` pivoting
   laterally over SMB/RPC to `.24/.25/.28`) - **100% flagged**, mean
   reconstruction error ~85x the benign-calibrated threshold.

2. **6 real, diverse Benign flows** (an RDP admin session, two DNS lookups,
   a 2-minute HTTPS download, a 1-minute HTTPS download, an ordinary internal
   HTTP transfer) - **also 100% flagged.**

That second result is the important one, and it overturns the first. A model
trained on 200 near-duplicate copies of one synthetic traffic shape
(seconds-scale, download-heavy, ~20-30 packets) isn't discriminating
"infiltration" from "benign" - it's discriminating "matches this one narrow
pattern" from "everything else." Real infiltration traffic and real ordinary
traffic (DNS, RDP, long downloads) both fall outside that narrow envelope, so
both get flagged identically. A detector with a 100% false-positive rate
"detects" 100% of attacks trivially and is useless in production - it would
page someone on every DNS query.

Run both yourself:

```
cargo test -p siem-ml --test infiltration_dataset -- --nocapture
```

**Conclusion:** the architecture (rules for noisy attacks, ML for quiet ones,
guarded response) is sound, but the current model has not demonstrated it
discriminates infiltration from benign traffic - only that it discriminates
"synthetic training shape" from everything else. Before this is trustworthy
against real traffic, the training/calibration set needs to be a large,
genuinely diverse real benign corpus (not synthetic, not narrow), and the
false-positive rate needs to be re-measured against that.

## Categorical attack-vector isolation (`siem-ml::classifier`)

Added after analyzing `spec_engine` (a companion crate in this workspace's
ecosystem): it classifies CIC-IDS2018 labels into MITRE ATT&CK tactics via
keyword matching (`classify_mitre_from_label`), which pointed at the right
fix for this project's autoencoder-only design - a single reconstruction-
error threshold can only ever answer "does this look like the one benign
pattern I trained on", which is both why it flagged 100% of real Infiltration
flows *and* 100% of real ordinary DNS/RDP/HTTPS traffic (see above). A
categorical system needs to ask a different question: "which of several
known shapes does this match, if any" - answered here with a small supervised
softmax classifier (`siem_ml::classifier::Classifier`) over six categories
(`Benign`, `Reconnaissance`, `BruteForce`, `Infiltration`,
`CommandAndControl`, `DenialOfService`), condensed from `spec_engine`'s MITRE
vocabulary down to shapes actually distinguishable at this crate's 8-feature
resolution.

**This is a different, complementary tool to the autoencoder, not a
replacement.** Supervised classification needs labeled examples of every
category it claims to distinguish - including attack examples - which is
exactly why it was *not* used to fix the autoencoder itself: retraining the
autoencoder on attack data would flip what "anomalous" means (it would learn
to reconstruct attacks well and flag benign traffic instead - this was
explicitly requested and declined earlier in this project's history for that
reason). Use both: the classifier for "which known category, if any" with a
confidence score callers can threshold on, and the autoencoder as an
open-set fallback for traffic that doesn't match any known category.

`crates/siem-ml/tests/categorical_isolation.rs` trains and evaluates it:

```
cargo test -p siem-ml --test categorical_isolation -- --nocapture
```

**Result: 28/29 (96.6%) test accuracy**, with a full confusion matrix printed
per run. The one error is informative, not concerning: a Benign flow
misclassified as Infiltration - consistent with the false-positive finding
above, since Benign and Infiltration are the two categories backed by real,
independently-varied data rather than jittered synthetic seeds.

**Data provenance matters here - read before trusting the number:**
- `Benign` (6 rows) and `Infiltration` (25-row subset of 50) are the real
  CIC-IDS2018-style data used throughout this project.
- `BruteForce`, `CommandAndControl`, and `DenialOfService` are seeded from
  `spec_engine`'s own synthetic dataset (1-3 real seed rows per category
  there), each jittered (+-15% on duration/packets/bytes) into a larger set
  purely to get a usable train/test split. This tests whether the classifier
  can separate these *shapes*, not whether it generalizes across
  independently-captured examples of each attack - a materially weaker claim
  than the Benign/Infiltration result.
- `Reconnaissance` is in the taxonomy (mirroring `spec_engine`'s vocab) but
  has no seed row in any dataset provided so far and is deliberately excluded
  from training/evaluation rather than backed by invented data.

## Honest gaps (not yet done)

- No real packet-capture source wired in - `siem-collector::synthetic_flow`
  stands in for what would be a `net_sys`/Zeek `conn.log` feed.
- **The autoencoder's training/calibration data is the core unresolved
  problem**, not a minor detail: it's a narrow synthetic set, and the false-
  positive test above shows it doesn't generalize to real diverse benign
  traffic. This needs a large real benign corpus and a proper percentile-
  based threshold (99th/99.9th) before it's meaningful, and even then the
  6-sample false-positive test here is too small to certify a rate - it's a
  smoke test, not a benchmark.
- The 50-row Infiltration sample is one campaign against one internal subnet;
  it doesn't establish how the model performs against different infiltration
  TTPs (DNS tunneling, ICMP exfil, encrypted C2 over unusual ports).
- The categorical classifier's `BruteForce`/`CommandAndControl`/
  `DenialOfService` categories rest on jittered variations of 1-6 real seed
  rows each (see the categorical section above) - real generalization
  testing needs independently-captured examples per category, the same gap
  the false-positive test exposed for the autoencoder. `Reconnaissance` has
  no backing data at all yet and isn't trained or evaluated.
- ~~No confidence-threshold/fallback wiring yet between the classifier and
  the autoencoder~~ - **done**, see `siem-review::to_flow_prediction`.
- ~~`siem-response::LogOnly` is a dry-run stub~~ - still true, and still the
  right default, but no longer the whole picture: a real executor
  (nftables/iptables rule, EDR API call) now only needs to implement
  `siem_response::ResponseAction` and gets the review gate for free. The
  executor itself still needs review before being wired in - that part of
  the original caveat stands.
- ~~Wazuh/OSSEC/Security Onion's "escalate to human review" had no real
  mechanism here either~~ - **done**, see `siem-review`/`review-queue`
  above. ~~What's still missing: the review queue's persistence
  (`store.rs`) isn't wired into the demo binary~~ - **also done**: `main.rs`
  now loads/saves `ReviewQueue` state via `review_queue::store` on every
  run (`REVIEW_QUEUE_STATE_PATH`, default `review_queue_state.json`).
  ~~plus the classifier's `predict` function extended to return the full
  softmax distribution so `ReviewTrigger`'s narrow-margin check (currently
  unused here, since only top-1 confidence is available) can apply~~ -
  **done**: `predict` now returns `runner_up_category`/
  `runner_up_confidence`, and `siem_review::to_flow_prediction` threads it
  through (see `siem-review`'s
  `narrow_runner_up_margin_forces_review_even_at_high_top1_confidence` test).
- ~~No persistence/storage layer for the SIEM's own event/alert data~~ -
  **done**, see the "Persistence" section above (`siem-store`, PostgreSQL).
  What's still missing there specifically: connection pooling (one
  `postgres::Client`, not a pool - wrong for a real concurrent-writer
  deployment), real migration *versioning* (the schema is additive-only,
  not evolvable against existing data without a tool like `sqlx-cli`), and
  the review-queue's audit graph still lives in a separate JSON file rather
  than the same Postgres database - querying "this alert AND its full
  review history" means two stores today, not one `JOIN`.
- **`siem-correlation`'s `ClamAvSender` has no real detector behind it.**
  There is no file-scanning/AV component in this codebase; the lane is
  fully wired and tested but only ever fed simulated events (clearly
  labeled as such in `siem-server`'s demo). Wiring a real scanner in is the
  actual remaining integration work, not a rename.
- **`siem-correlation`'s spectral lane has no real spectral-graph math
  behind it either** - `fiedler_shift` is always `0.0` (see
  `siem-correlation-bridge::ml_score_to_spectral`'s docs); this SIEM's
  `siem-ml` computes an autoencoder reconstruction error, not a graph
  Laplacian or Fiedler vector. The lane's *severity thresholds* are real
  and exercised; the specific "spectral" signal the name implies isn't.
- **Correlation state is in-memory only, unlike `review-queue` or
  `siem-store`.** A restart mid-window loses any partially-corroborated
  evidence for hosts that hadn't yet cleared the emission bar - no
  persistence layer backs `CorrelationEngine`'s per-host state the way
  `review_queue::store` and PostgreSQL back the other two.
- `siem-correlation` is the only `tokio`-based crate here; the rest of the
  pipeline is synchronous, and `siem-server`'s demo confines the async
  runtime to one `block_on`'d section rather than converting the whole
  binary - deliberate, to avoid a much larger unrelated change, but it
  means the correlation engine can't currently run continuously alongside
  the rest of the demo within one process the way a real deployment's
  long-running lanes would.
- `siem-notify` is genuinely best-effort: a failed webhook delivery is
  logged and dropped, not retried or queued for later delivery. Fine for
  its actual purpose here (a notification, not the decision itself, so a
  dropped one doesn't compromise anything the audit graph already
  recorded) - wrong if this ever needs delivery guarantees, which would
  need a real outbox/retry mechanism, not this crate's current one-shot
  `send_best_effort`.
- No multi-agent transport (gRPC/mTLS), no UI, no connection pooling,
  no real migration tool - this is the detection+response core plus its
  audit/persistence/correlation/notification layers, not yet a deployable
  product.
