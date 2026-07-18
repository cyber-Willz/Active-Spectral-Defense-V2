# Postgres + n8n + Power BI integration

## Architecture (and why it's shaped this way)

```
orchestrator.log  --tail-->  ingest.mjs  --INSERT-->  Postgres
                                  |
                                  '--POST (critical/high only)-->  n8n webhook
                                                                        |
                                                                  Route by Severity
                                                                        |
                                                                Slack/Email/Jira (you configure)

Power BI  --DirectQuery/Import-->  Postgres directly (no n8n in this path)
```

**n8n does not sit between Postgres and Power BI.** Power BI has a native
PostgreSQL connector and queries the database directly — routing that
through n8n would add a moving part with no benefit. n8n's job here is
the **alerting/response side**: turning "a host got auto-contained" into
a Slack ping or a ticket, which Power BI (a reporting tool, not an
automation tool) can't do.

The ingester is a separate process from the orchestrator on purpose: the
correlation engine's own docs say lane sends use `try_send` and drop
under load rather than block — a synchronous DB write inside that hot
path would reintroduce the exact stall it's designed to avoid. Tailing
the log keeps persistence fully decoupled and crash-safe (if the
ingester dies, the orchestrator keeps running; restart the ingester and
it catches up from where the log file left off... note: this reference
implementation re-reads from byte 0 on restart, so for a long-running
deployment add position checkpointing — see "Production notes" below).

## 1. Postgres

```bash
sudo -u postgres createuser -s asd
sudo -u postgres psql -c "ALTER USER asd WITH PASSWORD 'asd';"
sudo -u postgres createdb -O asd asd
sudo -u postgres psql -d asd -f persistence/schema.sql
```

Three tables (`verdicts`, `quarantine_events`, `containment_events`) plus
a `verdict_summary` view pre-aggregated by minute/disposition for a
quick first dashboard panel.

## 2. The ingester

```bash
cd persistence/ingester
npm install

ASD_PG_URL="postgres://asd:asd@localhost:5432/asd" \
ASD_N8N_WEBHOOK="http://localhost:5678/webhook/asd-alerts" \
node ingest.mjs ~/work/orchestrator.log
```

Leave it running alongside the orchestrator (same pattern as everything
else in this pipeline — a separate terminal or a `systemd` unit). It
parses three known log shapes (`verdict handled`, `quarantined file
path=`, `SIGHUP: rules reloaded`) and writes structured rows; anything
`Contained` or confidence ≥ 0.9 also fires the n8n webhook.

## 3. n8n

Installing n8n via `npm install -g n8n` pulls a dependency
(`sheetjs`'s CDN) that's blocked in some sandboxed/corporate network
environments — that's what happened when I tried it here. On your own
machine this is usually a non-issue, but **Docker is the more common way
most people run n8n anyway** and sidesteps it entirely:

```bash
docker volume create n8n_data
docker run -d --name n8n -p 5678:5678 -v n8n_data:/home/node/.n8n docker.n8n.io/n8nio/n8n
```

Then open `http://localhost:5678`, create your owner account, and
**import** `persistence/n8n-workflow-asd-alerts.json` (Workflows →
Import from File). It ships with:
- A **Webhook** node listening at `/webhook/asd-alerts` (matches
  `ASD_N8N_WEBHOOK` above)
- A **Switch** node routing on `severity` (`critical` / `high`)
- **Set** nodes formatting a human-readable message
- Two **NoOp** placeholder nodes marked "swap for Slack/Email/Jira" —
  replace these with whichever notification node fits your setup and
  point it at `{{$json.message}}`. Left as NoOp so the workflow imports
  and runs cleanly without a credential already configured.

Activate the workflow (top-right toggle), then re-run the ingester —
you should see executions appear in n8n's Executions tab.

## 4. Power BI

Power BI can't run in a Linux sandbox — this part happens on your own
Windows machine, connecting straight to Postgres (which itself can run
inside WSL2, or you can point Power BI at a Postgres instance running
anywhere reachable).

1. **Get Data → PostgreSQL database** (Power BI has this connector
   built in; if it prompts to install the Npgsql .NET driver, do that
   first — it's a one-time Windows-side install).
2. Server: `localhost:5432` (or your WSL2 IP if Power BI can't reach
   `localhost` directly — run `ip addr show eth0` inside WSL2 to get it).
   Database: `asd`.
3. Choose **DirectQuery** if you want the dashboard to reflect live
   data as the pipeline runs; choose **Import** for a periodically
   refreshed snapshot.
4. Credentials: Database — username `asd`, password `asd` (change this
   for anything beyond a local demo).
5. Pull in `verdicts`, `quarantine_events`, `containment_events`, and
   `verdict_summary`.

**Suggested first visuals:**
- Line chart: `verdict_summary.minute` (x) vs `n` (y), split by
  `disposition` — verdict volume over time.
- Card: `count(quarantine_events)` — total malware caught.
- Table: `verdicts` filtered to `confidence >= 0.9` — the auto-response
  candidates.
- Bar chart: `verdicts.host` vs count — which hosts are generating the
  most alerts.

## Production notes (beyond this demo scope)

- **Checkpoint the ingester's read position** (e.g. a small state file
  storing the last byte offset) instead of re-reading from 0 on every
  restart, once you're running this continuously rather than doing a
  one-off demo pull.
- **Rotate `orchestrator.log`** (e.g. via `logrotate`) once this runs
  for more than a session — it's unbounded right now.
- **Change the `asd`/`asd` Postgres credentials** before this touches
  anything beyond localhost.
- If log volume grows, consider switching the orchestrator's tracing
  output to `.json()` format (add the `json` feature to
  `tracing-subscriber` in `orchestrator/Cargo.toml`) instead of
  regex-parsing `key=value` pretty-print lines — more robust, though it
  does require a rebuild.
