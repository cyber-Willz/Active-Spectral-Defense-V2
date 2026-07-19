# active-spectral-defense

Integrates five previously-separate Rust projects into the single
pipeline drawn in `architecture_with_firewall_perimeter.svg`:

```
Firewall (perimeter)                                     [rustwall]
   |
Traffic ingestion                                         [rustwall]
   |------------------+--------------------+
   v                  v                    v
NSM fast path      ClamAV scan        Spectral engine        <- three lanes
(sig/rate/beacon)  (mail/file sig)    (HNSW + Jacobi)
   |                  |                    |
XDP enforcement    Quarantine          Anomaly scoring
(human-approved)   action              (spectral graph update)
   |                  |                    |
   +------------------+--------------------+
                       v
            Correlation engine (SIEM)                    [active-siem]
                       v
            Containment playbook
            (isolate host, block IP)
            /                          \
  rule sync                    containment feeds back
  (-> firewall, coarse          into anomaly scoring
   upstream rules)               (-> spectral engine)
```

## Layout

```
active_spectral_defense/
  Cargo.toml                 workspace: bridges/* + orchestrator only
  asd.example.toml           example orchestrator config
  components/                the five original projects, UNMODIFIED
    firewall-perimeter/         (was rustwall_with_ingestion/rustwall)
    nsm-xdp/                    (was nsm_xdp/nsm)
    rust-clam/                  (was rust-clam-production-ready-improved/rust-clam)
    spec-engine/                (was spectral_homology/spec_engine)
    active-siem/                (was active-siem/active-siem)
  bridges/                    new: the glue code this integration adds
    asd-xdp-bridge/             nsm alerts <-> siem-correlation::XdpSender
    asd-clamav-bridge/          rust-clam scans -> siem-correlation::ClamAvSender
    asd-spectral-bridge/        spec_engine <-> siem-correlation::SpectralSender
    asd-firewall-sync/          confirmed hosts -> rustwall policy (rule sync)
  orchestrator/               new: the binary that wires it all together
```

**Nothing under `components/` was changed.** Every integration point this
layer needed already existed in the original code (a Unix control socket
in `nsm`, a hot-reloadable TOML config in `rustwall`, public library APIs
in `spec_engine` and the `rust-clam`/`active-siem` crates) -- see each
bridge crate's module docs for exactly which API/file/socket it uses and
why.

## Why five workspaces, not one

`rustwall`, `nsm`, `rust-clam`, `spec-engine`, and `active-siem` each
shipped as their own Cargo workspace (some, like `rust-clam` and
`active-siem`, are themselves multi-crate). Merging five independent
workspaces (different `burn`/`tokio`/etc. version pins, some crates with
no `[lib]` target at all) into one is invasive and not worth it just to
add an integration layer on top. Instead, `bridges/*` and `orchestrator`
form their *own* small workspace (this directory's `Cargo.toml`) that
reaches into specific already-`pub` leaf crates under `components/` via
ordinary path dependencies. Cargo supports this fine -- each of those
leaf crates simply becomes part of this workspace's own dependency graph
and `Cargo.lock`, resolved independently from `components/*/Cargo.lock`.
`rustwall` and `nsm` have no `[lib]` target at all (they're
`[[bin]]`-only), so nothing here depends on them as libraries -- see
"Integration points" below for how each is actually driven.

## Integration points (what's real, what's glue)

| Arrow in the diagram | How it's implemented |
|---|---|
| NSM fast path -> XDP enforcement | `asd-xdp-bridge` tails `nsm`'s NDJSON alert stream (stdout, redirected to a file) and submits to `siem_correlation::XdpSender`, unconfirmed (`human_approved: false`). |
| ClamAV scan -> Quarantine action | `asd-clamav-bridge` watches per-host file-drop directories with `rust-clam`'s real `Scanner`/`QuarantineManager` and submits to `ClamAvSender`. |
| Spectral engine -> Anomaly scoring | `asd-spectral-bridge` runs live flow evidence through `spec_engine::QdrantSpectralSecurityEngine::ingest_cic` (a real trained autoencoder + real Laplacian/Fiedler computation) and submits to `SpectralSender`. |
| (fan-in) Correlation engine | `siem_correlation::CorrelationEngine`, used unmodified -- this is exactly what it's designed to do. |
| Containment playbook | `orchestrator/src/containment.rs`'s `ActiveContainment`, a `siem_response::ResponseAction` run by `siem_review::ReviewGatedResponse` once a verdict clears the human-review gate. |
| Rule sync (XDP enforcement -> firewall, coarse upstream rules) | `asd-firewall-sync` rewrites `rustwall`'s `asd_confirmed_malicious` alias + blocking rule in its TOML config, then `SIGHUP`s it to hot-reload. |
| Containment -> anomaly scoring | `asd-spectral-bridge::record_confirmed_threat` adds a permanent edge from the confirmed host to a shared "known threat" anchor entity in the spectral graph, biasing future scores for that host's neighborhood. |

Every bridge crate's module docs spell out exactly which upstream
function/file/socket it uses (with a source reference) and, under an
"Honest gaps" heading, where the mapping is partial rather than a full
reimplementation of something out of scope (e.g. CICFlowMeter-equivalent
feature extraction, or ClamAV's own host-attribution model, which doesn't
exist even in the original `rust-clam`).

## Wiring it up for real

This binary does **not** launch `rustwall` or `nsm` itself -- both need
root/CAP_NET_ADMIN and are the kind of thing you'd run under systemd or a
container supervisor independently of this orchestrator. It expects:

1. `rustwall` already running with `--config <firewall.config_path>`,
   its PID recorded in `asd.toml`.
2. `nsm` already running with `--xdp-control-socket <nsm.control_socket_path>`,
   stdout redirected to `<nsm.alert_log_path>`.
3. A Qdrant instance reachable at `<spectral.qdrant_url>` (`docker run -p
   6333:6333 -p 6334:6334 qdrant/qdrant`, same as `spec_engine`'s own
   README/`main.rs`).
4. One or more host-attributed drop directories for the ClamAV lane to
   watch (`clamav.watch_targets`).

Then:

```sh
cargo run --release -p active-spectral-defense -- --config asd.toml
```

This has not been compiled in the sandbox this was built in (no Rust
toolchain was available there -- every API call was checked by reading
the actual source in `components/`, not assumed from memory). Run `cargo
check` first in a real environment; `spec_engine`'s `burn`/`qdrant-client`
dependency tree is large and the first build will take a while.

## Honest gaps (integration-layer-wide)

- **Spectral feature mapping is partial.** `spec_engine` was trained
  against a ~52-dimension CIC-IDS2018-style feature vector; live capture
  (`nsm`) doesn't compute that full feature set (no CICFlowMeter-
  equivalent IAT/active-idle timing extraction). `asd-spectral-bridge`
  fills what it can from `nsm` alert metadata and leaves the rest at
  neutral defaults -- scores are real (computed by the real trained
  model against a real graph), just from a partial feature vector. See
  that crate's module docs for the specifics.
- **ClamAV host attribution is a configured mapping, not inferred.**
  `rust-clam` has no host concept at all; `asd-clamav-bridge` requires an
  explicit directory-to-host table (`clamav.watch_targets`).
- **The spectral engine's baseline is the CIC-IDS2018 sample dataset's
  benign rows**, same as `spec_engine`'s own `run()` demo, not a live
  captured baseline -- see `orchestrator/src/main.rs`'s comment on this
  and `spec_engine::bootstrap`'s doc comment (which describes exactly
  this trade-off for live-traffic integrations).
- **No SLA sweep loop.** `siem-review`'s `ReviewQueue` needs
  `sweep_expired(sla_seconds)` called periodically to resolve
  human-review items that time out; this reference orchestrator doesn't
  run that loop yet (a natural next addition -- see `siem-review`'s own
  docs on `SlaPolicy`).
- **Config reload of `firewall.pid`** is static in `asd.toml`; if
  `rustwall` restarts and gets a new PID, this needs updating (or the
  config, and this binary, extended to read a pidfile instead).



# active-spectral-defense — end-to-end live run
 
Concise command reference. Run everything from a Linux shell (native
Linux, or WSL2). Each numbered daemon step should run in its own
terminal, or backgrounded as shown.
 
---
 
## 0. Toolchain
 
```bash
# Rust >=1.85 required. Easiest path: rustup (sidesteps stale apt repos).
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustc --version   # confirm >=1.85
 
sudo apt-get update
sudo apt-get install -y pkg-config libssl-dev postgresql
```
 
## 1. Unpack
 
```bash
mkdir -p ~/work && cd ~/work
tar xzf active_spectral_defense_complete.tar.gz
cd active_spectral_defense
```
 
## 2. Qdrant (real binary, not a stub)
 
```bash
cd ~/work
curl -sL "https://github.com/qdrant/qdrant/releases/download/v1.18.3/qdrant-x86_64-unknown-linux-gnu.tar.gz" -o qdrant.tar.gz
tar xzf qdrant.tar.gz && chmod +x qdrant
mkdir -p qdrant_storage
 
QDRANT__STORAGE__STORAGE_PATH=~/work/qdrant_storage \
QDRANT__TELEMETRY_DISABLED=true \
setsid nohup ./qdrant > ~/work/qdrant.log 2>&1 < /dev/null &
 
sleep 4 && curl -s http://localhost:6333/    # expect {"title":"qdrant"...}
```
 
## 3. Build
 
```bash
cd ~/work/active_spectral_defense
 
# bridges + spectral engine
cargo build --release -p asd-xdp-bridge -p asd-clamav-bridge \
  -p asd-spectral-bridge -p asd-firewall-sync
 
# orchestrator (pulls in the vendored burn-core patch automatically)
cargo build --release -p active-spectral-defense
 
# containment demo harness (proves the containment -> firewall SIGHUP leg)
cargo build --release -p containment-demo
 
# rustwall — build from an isolated copy so its own [workspace] doesn't
# collide with the parent workspace
cp -r components/firewall-perimeter ~/work/rustwall_build
(cd ~/work/rustwall_build && cargo build --release)
 
# nsm
(cd components/nsm-xdp && cargo build --release)
```
 
## 4. Runtime dirs, configs, permissions
 
```bash
sudo mkdir -p /var/run/asd /var/lib/asd/quarantine \
  /var/lib/asd/dropzone/198.51.100.7 /etc/rustwall
 
# Hand ownership to yourself -- avoids sudo on every later write/signal.
sudo chown -R "$USER:$USER" /var/run/asd /var/lib/asd /etc/rustwall
 
sudo tee /etc/rustwall/asd-managed.toml > /dev/null << 'EOF'
queue_num = 0
queue_workers = 2
default_policy = "drop"
log_max_per_sec = 200
quarantine_max_entries = 100000
sync_to_os_firewall = false
trusted = ["10.0.0.1"]
 
[[aliases]]
name = "office"
cidrs = ["10.0.0.0/24"]
 
[[aliases]]
name = "known_scanners"
cidrs = ["198.51.100.0/24"]
EOF
```
 
`asd.toml` (already shipped at the workspace root — edit `pid` after step 5):
 
```bash
cd ~/work/active_spectral_defense
cat asd.toml   # confirm it exists; [firewall].pid gets patched next
```
 
## 5. Launch rustwall (real NFQUEUE bind)
 
NFQUEUE needs `CAP_NET_ADMIN`/`CAP_NET_RAW`. Grant the capability once
instead of running as root, so the process — and everything that later
writes to its config or signals it — stays owned by your own user:
 
```bash
sudo setcap cap_net_admin,cap_net_raw+ep ~/work/rustwall_build/target/release/rustwall
 
cd ~/work/rustwall_build
setsid nohup ./target/release/rustwall --config /etc/rustwall/asd-managed.toml \
  > ~/work/rustwall.log 2>&1 < /dev/null &
 
sleep 2
RWPID=$(pgrep -f "rustwall --config" | tail -1)   # tail -1: skip any sudo wrapper PIDs
echo "rustwall pid: $RWPID"
tail -5 ~/work/rustwall.log     # look for "nfqueue worker bound, entering packet loop"
 
cd ~/work/active_spectral_defense
sed -i "s/^pid = .*/pid = $RWPID/" asd.toml
grep "^pid" asd.toml
```
 
> If `setcap` isn't available or NFQUEUE still refuses to bind (some
> WSL2 kernels lack `nfnetlink_queue`), fall back to `sudo ./rustwall
> --config ...` run in the foreground in a second terminal, and use
> `sudo kill -HUP $RWPID` wherever a signal is needed later.
 
## 6. Launch nsm (synthetic detection traffic)
 
```bash
cd ~/work/active_spectral_defense/components/nsm-xdp
setsid nohup ./target/release/nsm --simulate \
  > /var/run/asd/nsm-alerts.ndjson 2> ~/work/nsm.stderr.log < /dev/null &
 
sleep 2
wc -l /var/run/asd/nsm-alerts.ndjson   # expect ~67 lines; process exits when the scenario finishes -- that's normal
```
 
## 7. Launch the orchestrator
 
```bash
cd ~/work/active_spectral_defense
RUST_LOG=info setsid nohup ./target/release/active-spectral-defense --config asd.toml \
  > ~/work/orchestrator.log 2>&1 < /dev/null &
 
sleep 5
tail -f ~/work/orchestrator.log
# Ctrl+C to stop watching -- the process itself keeps running in the background
```
 
You should see spectral bootstrap (`Pretraining autoencoder ...`), then
real `[ANOMALY]` and `verdict handled` lines as nsm's alerts get scored
and correlated.
 
## 8. Trigger a live ClamAV detection
 
```bash
printf 'test malware payload' > /var/lib/asd/dropzone/198.51.100.7/live_drop.bin
sleep 2
grep quarantined ~/work/orchestrator.log
ls /var/lib/asd/quarantine/
```
 
## 9. Exercise containment -> firewall-sync directly
 
Verdicts in synthetic traffic typically stay below the 0.90
auto-response threshold, so this step proves the containment leg
directly rather than waiting on one to clear the review gate:
 
```bash
cd ~/work/active_spectral_defense
RWPID=$(pgrep -f "rustwall --config" | tail -1)
./target/release/containment-demo "$RWPID"
 
tail -3 ~/work/rustwall.log      # look for "SIGHUP: rules reloaded"
cat /etc/rustwall/asd-managed.toml   # confirmed-host alias + drop rule now present
```
 
---
 
## 10. Persistence layer (Postgres + n8n alerting + Power BI)
 
### 10a. Postgres
 
```bash
sudo -u postgres createuser -s "$USER" 2>/dev/null
sudo -u postgres psql -c "ALTER USER $USER WITH PASSWORD 'asd';"
sudo -u postgres createdb -O "$USER" asd
psql -d asd -f ~/work/active_spectral_defense/persistence/schema.sql
```
 
### 10b. Ingester (tail logs -> Postgres, alert on high-signal events)
 
Run once per log source — the orchestrator's log for verdicts/quarantine,
rustwall's log for containment/SIGHUP events:
 
```bash
cd ~/work/active_spectral_defense/persistence/ingester
npm install
 
ASD_PG_URL="postgres://$USER:asd@localhost:5432/asd" \
ASD_N8N_WEBHOOK="http://localhost:5678/webhook/asd-alerts" \
setsid nohup node ingest.mjs ~/work/orchestrator.log \
  > ~/work/ingester-orch.log 2>&1 < /dev/null &
 
ASD_PG_URL="postgres://$USER:asd@localhost:5432/asd" \
ASD_N8N_WEBHOOK="http://localhost:5678/webhook/asd-alerts" \
setsid nohup node ingest.mjs ~/work/rustwall.log \
  > ~/work/ingester-rustwall.log 2>&1 < /dev/null &
```
 
Verify:
 
```bash
psql -d asd -c "SELECT ts, host, disposition, confidence FROM verdicts ORDER BY ts;"
psql -d asd -c "SELECT ts, file_path, signature FROM quarantine_events;"
psql -d asd -c "SELECT ts, event_type, rule_count FROM containment_events;"
```
 
### 10c. n8n (alerting — Docker avoids the npm CDN dependency issue)
 
```bash
docker volume create n8n_data
docker run -d --name n8n -p 5678:5678 -v n8n_data:/home/node/.n8n docker.n8n.io/n8nio/n8n
```
 
Open `http://localhost:5678` → create owner account → **Import from
File** → `persistence/n8n-workflow-asd-alerts.json` → swap the two NoOp
placeholder nodes for Slack/Email/Jira → **Activate**.
 
### 10d. Power BI (on your Windows machine, not WSL2/Linux)
 
**Get Data → PostgreSQL database** → server `localhost:5432` (or your
WSL2 IP if unreachable directly — `ip addr show eth0` inside WSL2) →
database `asd` → DirectQuery for live data. See
`persistence/SETUP.md` for suggested visuals.
 
---
 
## Full teardown
 
```bash
pkill -f "active-spectral-defense --config"
pkill -f "rustwall --config"
pkill -f "nsm --simulate"
pkill -f "ingest.mjs"
pkill -f "./qdrant"
sudo -u postgres pg_ctlcluster 16 main stop
docker stop n8n
```
