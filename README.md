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
