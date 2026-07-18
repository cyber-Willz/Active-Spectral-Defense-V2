# rust-clam

A Rust malware scanner: a hash + wildcard signature engine, zip/gzip/tar
archive recursion with hard-enforced bomb protection, and PE
packer/structural heuristics. Ships as a one-shot CLI (`rclam`), an async
scanning daemon (`rclamd`) speaking a `clamd`-compatible protocol subset,
and a real-time on-access monitor with quarantine management
(`rclam-watch`).

This is a Cargo **workspace** (multiple crates, no root binary) — `cargo
run` at the top level has nothing to run by itself. Use one of:

```powershell
# from the workspace root (C:\...\clam\ in your layout)
cargo run -p rclam-cli --bin rclam -- --ndb signatures\sample.ndb --hdb signatures\sample.hdb <path-to-scan>
cargo run -p rclam-daemon --bin rclamd -- --ndb signatures\sample.ndb
cargo run -p rclam-watch --bin rclam-watch -- --ndb signatures\sample.ndb watch <path-to-watch>

# or, cd into the crate itself, then plain `cargo run` works:
cd crates\rclam-cli
cargo run -- --ndb ..\..\signatures\sample.ndb <path-to-scan>
```

## Building

```
cargo build --release --workspace
```

Binaries land in `target/release/rclam`, `rclamd`, and `rclam-watch`.

Requires a Rust toolchain new enough for edition 2021. The checked-in
`Cargo.lock` deliberately pins several dependencies below their latest
release (`rayon-core` to `1.12.1`, `zeroize` to `1.7.0`, `time` to
`0.3.36`, `crc` to `3.0.1`) rather than letting them float to whatever's
newest, so the workspace keeps building on toolchains as old as 1.75
without every contributor needing the absolute latest stable release —
several of those pins exist specifically because of the 7z/cab/AEAD
additions in this round (`sevenz-rust`, `cab`, and `chacha20poly1305`'s
transitive dependency trees all had newer releases requiring edition 2024,
which stable 1.75 doesn't support). CI additionally tests on the latest
stable release, so a genuinely newer MSRV requirement from a future
dependency bump would still be caught there even though it's not enforced
locally.

## Running the test suite

```
cargo test --workspace
```

`cargo test --workspace` runs the full suite across `sig-engine`,
`archive-guard`, `pe-analyze`, `scanner-core`, and `rclam-daemon` (60 tests
total), covering (among other things): the archive-recursion depth guard,
zip/gzip/tar-bomb total-size/ratio guards, empty-file handling,
non-regular-file (FIFO/device) rejection, oversized-file skipping,
checked-arithmetic PE header parsing, the scan-path allowlist (including
symlink-escape attempts), per-peer rate/concurrency limiting, and eight
integration tests that drive real `TcpStream` connections through the
daemon's TCP transport end-to-end (`PING`/`VERSION`/`SCAN`/`STATS`,
allowlist denial, oversized-command handling) -- this is the exact code
path Windows uses exclusively, previously compiled on Windows CI but never
functionally exercised there; these tests now run, and pass, on every OS
in the CI matrix.

`sig-update/` (the signature-update tool) is a separate, detached
workspace with its own 17 tests -- see the Signature updates section
below.

```
cargo clippy --workspace --all-targets
cargo fmt --all -- --check
```

## Signature file formats

- `--ndb <file>`: wildcard byte-pattern signatures, `name:hexpattern` per
  line. `??` = single wildcard byte, `*` or `*{min-max}` = variable gap.
- `--hdb <file>`: exact-hash signatures, `hexhash:size:name` per line
  (`size` may be `*` for any size; hash may be MD5/SHA1/SHA256 by length).

Both flags may be repeated to load multiple database files.

## Archive recursion

Both the CLI and the daemon recurse into archive contents automatically:

- **Zip** (`PK\x03\x04` magic): every entry is extracted and scanned,
  including entries that are themselves zips, down to `--max-depth`.
- **Gzip** (`1F 8B` magic), including concatenated gzip members: the
  decompressed stream is fed back through the scanner as one logical
  child, e.g. `payload.bin.gz -> (gunzip)`.
- **Tar** (POSIX `ustar` magic at header offset 257): every regular-file
  entry is extracted and scanned, including a tar member that is itself an
  archive. Combined with gzip recursion above, this covers `.tar.gz`
  transparently — the gzip layer decompresses, the result is detected as
  tar, and each member is scanned individually. Legacy V7 tar (no magic
  field at all) is not detected, since there's no magic to reliably anchor
  detection on without risking false positives on arbitrary binary data.
- **7z** (`37 7A BC AF 27 1C` magic, via the `sevenz-rust` crate): every
  entry with content is extracted and scanned, same recursion/budget rules
  as everything else. One 7z-specific caveat: for a *solid* archive
  (multiple files sharing one compressed block, common with 7z), aborting
  extraction early because a byte-budget limit tripped stops this scan
  from buffering more than the budget allows, but doesn't necessarily save
  the CPU cost of decompressing the rest of an in-progress solid block —
  an inherent property of the format shared by every 7z-capable scanner,
  not something specific to this implementation.
- **Cab** (`MSCF` magic, via the `cab` crate): every file entry across
  every folder is extracted and scanned, same rules again.

Every byte that comes out of an archive is charged against a shared
`GuardBudget` (entry count, total uncompressed size, per-entry
compression ratio, and recursion depth), and extraction is aborted the
instant any limit is crossed — the limits are structural, not
configuration that a specific decoder could bypass. A file that isn't a
recognized archive format is simply signature/PE-scanned as-is; there's no
"unsupported archive" error path a bomb could hide behind.

**RAR is still not supported**, and that's a deliberate scoping decision
rather than an oversight: RAR's compression is a proprietary format, and
every Rust crate offering RAR *extraction* (as opposed to just reading
archive metadata) either wraps the non-free `libunrar` via FFI/bindgen
(a runtime dependency on a closed-source system library, and a licensing
mismatch with this project's otherwise all-permissive dependency tree) or
doesn't yet implement enough of RAR5's compression to be usable. A file in
RAR format is scanned as opaque bytes rather than recursed into — not a
crash risk, a detection gap, exactly like every other unrecognized format.
If a genuinely permissively-licensed pure-Rust RAR5 decoder matures, this
is the natural place to add it.

## Resource limits

`GuardLimits` (re-exported from `scanner-core` as well) controls:

| Field                     | Default   | Purpose |
|---------------------------|-----------|---------|
| `max_depth`                | 16        | nested-archive recursion depth |
| `max_entries`               | 10,000    | entries extracted per archive |
| `max_total_uncompressed`   | 4 GiB     | cumulative decompressed bytes, whole recursive scan |
| `max_ratio`                 | 1000      | per-entry (uncompressed / compressed) ratio |
| `read_chunk`                | 1 MiB     | single read-call size cap |
| `max_file_size`             | 200 MiB   | top-level file size scanned directly (larger files are **skipped**, not erred) |

Both `rclam` and `rclamd` expose `--max-file-size` and `--max-depth` on the
command line; the rest are currently fixed at their defaults (extend
`Args` in either binary if you need to tune them further).

Files that aren't plain regular files (FIFOs, sockets, device nodes) are
never opened for scanning at all — the check happens via `stat`, before
any `open()` call, specifically so a FIFO with no writer on the other end
can't block a scan indefinitely.

## CLI exit codes

`rclam` follows `clamscan`'s convention, since scripts and CI pipelines
depend on being able to tell these apart:

- `0` — scan completed, nothing found
- `1` — scan completed, at least one infected/detected file
- `2` — an operational error (bad signature file, unreadable path, i/o error)

`rclam` also accepts `--quarantine` (with `--quarantine-dir`, default
`/var/lib/rclam/quarantine`) to move any confirmed detection into
quarantine immediately after an on-demand scan, using the same
`rclam-quarantine` crate described below.

## Real-time protection & quarantine (`rclam-watch`)

`rclam-watch` is an on-access monitor: it watches one or more directories
recursively (via the OS's native filesystem-event API through the
`notify` crate) and runs every created/modified file through the exact
same `scanner-core::Scanner` used by `rclam` and `rclamd` — same archive
recursion, same bomb guards, same PE heuristics, same signature engine.
There's no separate, weaker code path for "real-time" scanning.

```
rclam-watch --ndb signatures/sample.ndb --hdb signatures/sample.hdb \
  watch /home/alice/Downloads /home/alice/Desktop \
  --exclude-path /home/alice/Downloads/build \
  --exclude-ext log \
  --auto-quarantine
```

- **Debounced**: a burst of write events against the same path within
  `--debounce-ms` (default 500) collapses into one scan, and the file is
  given a brief moment to finish flushing before it's read at all, so an
  in-progress write isn't scanned half-written.
- **`--auto-quarantine` is opt-in, off by default.** Without it,
  `rclam-watch` only logs detections (`WARN` level) and never touches a
  file — the safer default for a first deployment, consistent with this
  codebase's general fail-closed posture (see `rclamd`'s `--allow-root`
  above). With it, the file is read exactly once, scanned via
  `Scanner::scan_in_memory` against that one buffer, and — on a
  confirmed detection — quarantined using that same buffer (via
  `QuarantineManager::quarantine_bytes`), with the original only removed
  after the neutralized copy is confirmed on disk. Scanning and
  quarantining off the same read (rather than scanning once, then
  re-reading the file separately to quarantine it) closes what would
  otherwise be a TOCTOU gap between "what got scanned" and "what got
  quarantined."
- **`--exclude-path`** (a real path prefix, compared component-by-
  component via `Path::starts_with` — *not* a text/string prefix, so
  excluding `/tmp` does not also exclude the unrelated directory `/tmp2`)
  and **`--exclude-ext`** keep noisy or irrelevant paths out of the scan
  queue entirely; the quarantine directory itself is always excluded
  automatically so a monitor watching one of its ancestors can't rescan
  its own output.
- **Filename heuristic**: every scanned file's name is also checked for
  the "benign-looking extension followed by an executable one" pattern
  (`invoice.pdf.exe`) via `pe_analyze::suspicious_filename` — a
  content-independent signal that content-based scanning can't catch on
  its own, logged alongside (not instead of) the signature/PE scan result.

Quarantine management is its own subcommand, sharing the same
`--quarantine-dir`:

```
rclam-watch --quarantine-dir /var/lib/rclam/quarantine quarantine list
rclam-watch --quarantine-dir /var/lib/rclam/quarantine quarantine restore <id> --to /tmp/recovered.bin
rclam-watch --quarantine-dir /var/lib/rclam/quarantine quarantine delete <id>
rclam-watch --quarantine-dir /var/lib/rclam/quarantine quarantine verify <id>
```

`rclam-quarantine` (the crate underneath both `rclam-watch quarantine`
and `rclam`'s `--quarantine` flag) neutralizes a file with
**ChaCha20-Poly1305** — a real AEAD stream cipher, keyed with fresh random
material generated per file — before storing it, then removes the
original only after the neutralized copy is confirmed written to disk.
This is still **not** meant to protect confidentiality from an operator
who controls the quarantine store: the decryption key lives right
alongside the ciphertext, in the sidecar `.json` record, because restoring
a file is a normal, supported operation for that operator. What it adds
over the naive repeating-key XOR this used to be:

- **No known-plaintext keystream recovery.** For a detected file, the
  signature that matched is by definition already public — an attacker
  who knows some of the plaintext at one offset should never be able to
  use that to decrypt the rest. A repeating-key XOR keystream fails this
  (recover the short repeating key from one known block, decrypt
  everything); ChaCha20's keystream is a full permutation of the
  nonce+counter, so it doesn't.
- **Tamper-evidence.** The Poly1305 authentication tag means a corrupted
  or bit-flipped quarantine file fails to decrypt cleanly — `restore` and
  the new `verify` subcommand both report a clean
  `IntegrityCheckFailed` error rather than silently handing back garbage
  that looks like a legitimate restore. `verify` in particular lets an
  operator sweep the quarantine store periodically and get a real answer
  to "has anything in here been tampered with since it was quarantined?"
  without needing to restore anything to find out.

Every quarantine action (and every restore) is logged at `WARN` level,
since both are meant to be visible, deliberate events, not silent
automation.

## `rclamd` daemon

```
rclamd --ndb signatures/sample.ndb --hdb signatures/sample.hdb
```

- **Transport**: a Unix domain socket on Linux/macOS (`--socket <path>`,
  default `/tmp/rclamd.sock`), a TCP loopback socket on Windows
  (`--port <n>`, default `3310`). Force TCP on Unix too with `--tcp`. Both
  transports run through one identical protocol handler.
- **Protocol**: `PING`, `VERSION`, `SCAN <path>` / `CONTSCAN <path>`,
  `SHUTDOWN` — one command per connection, newline-terminated.
- **Socket permissions**: the Unix socket is chmod'd to `--socket-mode`
  (default `0600`, owner-only) right after binding. `clamd`'s historical
  default of a group-writable socket has been a recurring
  privilege-escalation footgun in deployments that got the surrounding
  group membership wrong; the safer default is chosen here and left to the
  operator to loosen deliberately.
- **Concurrency limiting**: `--max-connections` (default 64) bounds how
  many scans run at once, daemon-wide. Once saturated, new connections are
  told `ERROR server busy, try again later` and closed immediately rather
  than queued — this bounds worst-case latency and fd/memory use under
  load instead of degrading silently.
- **Per-peer rate and concurrency limiting**: independent of the daemon-wide
  cap above, `--peer-rate-per-sec` (default 5), `--peer-burst` (default 20),
  and `--peer-max-concurrent` (default 8) bound a *single* client sharing
  the daemon with others. Without this, one noisy or malicious client could
  consume most of `--max-connections` by itself and starve every other
  tenant. "Peer" is the connecting user's uid over a Unix socket
  (`SO_PEERCRED`, via `peer_cred()`) or the source IP over TCP, so two
  local users sharing one daemon are limited independently of each other.
  Rejected connections get `ERROR rate limit exceeded` or `ERROR too many
  concurrent connections from this peer` and are closed, same
  fail-fast/no-queueing philosophy as the global cap.
- **Scan path allowlist (fails closed)**: socket permissions control *who*
  can connect, not *what* a connected client may then ask to be scanned.
  `--allow-root <dir>` (repeatable) is the layer that answers that second
  question: a `SCAN`/`CONTSCAN` request is only honored if the requested
  path canonicalizes (symlinks resolved, so a symlink inside an allowed
  root pointing outside it doesn't grant access) to somewhere underneath
  one of the configured roots. **With no `--allow-root` configured, every
  scan request is refused** — a shared daemon with no explicit roots has no
  safe default other than "scan nothing." Denials are deliberately generic
  (`ERROR access denied`, no distinction between "outside the allowlist"
  and "doesn't exist") so an unprivileged client can't use the daemon as a
  filesystem-existence oracle against paths it has no business probing.
- **Metrics and health**: `--metrics-addr`/`--metrics-port` (default
  `127.0.0.1:9310`, set `--metrics-addr ""` to disable) serve `GET
  /healthz` (plain `200 ok`) and `GET /metrics` (Prometheus text format:
  connection/scan/rejection counters, uptime, free connection-queue slots).
  A `STATS` protocol command is also available for the same counters
  without needing a separate HTTP client. This is what an orchestrator
  needs to page on "the scan queue is growing," not just "the process
  crashed" (which logs alone already covered).
- **DoS-resistant command parsing**: a client that never sends `\n` cannot
  make the daemon buffer unbounded data per connection — the command line
  read is capped at 8 KiB, past which the connection is closed with
  `ERROR command line too long`.
- **Graceful shutdown**: `SIGTERM` or Ctrl+C stops the accept loop and (on
  Unix) removes the socket file, instead of the process being killed
  mid-request by an unhandled signal.
- **Resilience by design**: the workspace profile deliberately keeps
  `panic = "unwind"`. If a single scan request somehow panics, tokio
  catches it at the task boundary — only that one connection is lost, the
  daemon keeps serving everything else. (`panic = "abort"` would trade
  that away for a smaller binary, the wrong trade for a long-running
  service.)
- **Logging**: structured logs via `tracing`, to stderr, controlled with
  `RUST_LOG` (e.g. `RUST_LOG=debug rclamd ...`). Scan *results* on the
  CLI's stdout and the daemon's protocol responses are unaffected by log
  verbosity — they're the tool's actual output, not diagnostics.
- **Startup failures don't panic**: a bad `--ndb`/`--hdb` file logs a clear
  error and exits with a nonzero status, rather than an `unwrap`/`expect`
  panic backtrace.

### Deployment

- `deploy/rclamd.service` — a hardened systemd unit (dedicated user,
  `ProtectSystem=strict`, `NoNewPrivileges`, restricted address families,
  etc). Adjust `ReadOnlyPaths` to whatever directory clients will ask it
  to scan.
- `Dockerfile` — multi-stage build, runs as an unprivileged `rclam` user,
  exposes the TCP transport on `3310`.

```
docker build -t rclam .
docker run --rm -p 3310:3310 -v /path/to/scan:/scan:ro rclam
```

## Signature updates

`sig-update/` is a separate `freshclam`-equivalent CLI (`rclam-sigupdate`),
detached from the main workspace (own `Cargo.toml`, own dependency
resolution) since its dependencies (`ed25519-dalek`, `ureq`) have a higher
MSRV than the daemon's own pinned dependency set:

```
rclam-sigupdate --manifest-url https://sigs.example.com/manifest.json \
    --sig-dir /etc/rclam/signatures \
    --public-key <hex ed25519 pubkey>   # optional but recommended
```

It fetches a small JSON manifest (version + per-file name/sha256/url),
verifies every downloaded file's SHA-256 against it, stages everything in a
temp directory, and only then atomically swaps that directory into place
as `--sig-dir` — nothing in the live signature directory is touched until
every file has verified. The previous generation is kept as
`<sig-dir>.previous` for a one-step rollback (`sig_update::rollback`).
With `--public-key`, it additionally requires and verifies a detached
Ed25519 signature over the manifest itself (fetched from
`<manifest-url>.sig`), which is what catches a compromised or spoofed
*origin*/CDN rather than just an on-path tampering attempt (TLS on the
manifest fetch already covers the latter).

The full fetch → verify → stage → atomic-swap pipeline is exercised
end-to-end against a **real local TLS server** (`rustls` + a freshly
minted self-signed cert via `rcgen`, in
`sig-update/src/bin/rclam_sigupdate.rs`'s own `tls_end_to_end_tests`
module) — an actual TLS 1.2/1.3 handshake and record layer, the same
`rustls` stack `ureq` uses in production here, not a plain-HTTP stand-in.
One of those tests deliberately tampers with a served file's declared
SHA-256 and confirms both that the update is rejected *and* that the live
signature directory is left completely untouched. Writing that test also
caught a real bug: the crate had `ureq`'s `rustls` feature enabled (which
only pulls in the dependency) but not its `tls` feature (which is what
actually wires up HTTPS support and the `webpki-roots` CA bundle) — as
shipped, `rclam-sigupdate` could not actually make an HTTPS request at
all. Fixed by switching to the `tls` feature, which also gives production
use verification against the standard Mozilla root CA bundle by default,
not just against a runtime-supplied trust root as before.

What that test setup still can't cover — a self-signed cert trusted
explicitly is not the same as certificate-chain validation against the
public WebPKI, and localhost is not a real network path — is a genuine
"run it against a production distribution point" validation; that remains
real follow-up work before depending on this against a real CDN/origin.

Separately, `sig-update/src/apply.rs` has dedicated tests for two
conditions the atomic-swap logic exists to handle safely: concurrent
updates racing to swap into the same `sig_dir` (two real threads, a
`Barrier` to force them as close to simultaneous as the scheduler allows —
the property under test is that `sig_dir` always ends up as exactly one
complete generation, never a mix of two), and an update that fails before
touching anything live (a blocked `.previous` slot) leaving the existing
signatures completely untouched. A true crash-*during*-the-swap (kill -9
between the two `rename` calls) is not further testable beyond that:
`rename(2)`'s atomicity is a single-directory-entry-operation guarantee
from the OS/filesystem itself, not something this code's own logic could
partially fail at.

Run it from cron or a systemd timer, the same way `freshclam`
traditionally is; it does not run as its own daemon.

## Fuzzing

`fuzz/` is a `cargo-fuzz` scaffold covering the eight parsers that consume
fully attacker-controlled bytes: PE headers, `.ndb`/`.hdb` signature
definitions, and the zip/gzip/tar/7z/cab extractors. Every target
type-checks against the current APIs. `.github/workflows/ci.yml` now has a
`fuzz-run` job that actually executes coverage-guided fuzzing for every
target (`cargo fuzz run <target> -- -max_total_time=120`) on a daily
schedule and on manual dispatch — real execution, not just a build check,
and it uploads the failing input as a CI artifact if one is found.

That job runs on GitHub's own runners specifically because they have full
internet access for the nightly toolchain `cargo-fuzz` needs; several of
these targets (including the new 7z/cab ones) were written from a
sandboxed environment that couldn't install one, so `cargo +nightly fuzz
run` has not been exercised from *that* environment. In the meantime,
`proptest`-based property tests in `archive-guard`, `pe-analyze`, and
`sig-engine` cover the same "never panic on adversarial input" property
and run today, on stable, on every `cargo test` — not coverage-guided the
way libFuzzer is, but real, currently-executing adversarial-input testing
rather than a promise of future testing. They already found and fixed a
real bug this way: `sig-engine`'s hex-signature parser panicked on
non-ASCII UTF-8 input (a raw byte-offset slice into a `&str` that could
land inside a multi-byte character) — see `sig-engine/src/hexsig.rs` and
its checked-in `proptest-regressions/` seed. See `fuzz/README.md` for
exact commands and the reasoning behind each target.

## Dependency auditing

`cargo audit` passes clean (0 advisories against 106 crate dependencies) as
of this change. It previously never completed a run in practice; running
it surfaced one real advisory (`RUSTSEC-2026-0204`, an invalid-pointer
dereference in `crossbeam-epoch`'s `fmt::Pointer` impl, pulled in
transitively via `rayon`), fixed here by bumping `crossbeam-epoch` to
0.9.20 in `Cargo.lock`. Re-run `cargo audit` yourself before relying on
that claim staying true — it's a statement about the dependency tree today,
not a permanent property of the project.

## CI


`.github/workflows/ci.yml` runs, on every push/PR: build + test on
Linux/macOS/Windows, `cargo fmt --check`, `cargo clippy -D warnings`,
`cargo audit` against the dependency tree, and a `fuzz-build` job that
compiles (but does not run) every `cargo-fuzz` target so API drift between
the fuzz harness and the scanned crates is caught immediately.

## Design notes / threat-model callouts

A few decisions in this codebase are deliberate responses to known
historical AV-scanner CVE classes, and are worth knowing about if you're
extending it:

- **No bytecode VM for signatures** (`sig-engine`): matching is pure
  data-driven segment verification. There's no interpreted signature
  language, which removes an entire historical CVE class (malformed-
  bytecode memory corruption in the scanner itself, as ClamAV has hit
  repeatedly).
- **Structural, not configurable, archive limits** (`archive-guard`):
  every extraction call is threaded through a `GuardBudget` decremented as
  bytes come out; there's no code path that produces archive contents
  without going through the budget check.
- **Bounds-checked PE parsing** (`pe-analyze`): every field access goes
  through `get_*` helpers and `checked_add`/`checked_mul` rather than raw
  pointer casts or plain arithmetic over attacker-controlled offsets — a
  malformed or truncated PE can only produce an `Err`, never UB or an
  offset that wraps past a bounds check on a 32-bit target.
- **Stat-before-open** (`scanner-core`): file-type checks happen via
  `stat`, before `File::open` is ever called, because opening a FIFO for
  reading blocks until a writer connects — checking the type *after*
  opening would be too late to prevent the hang.

## Known limitations, as of this change

Honest accounting of what's still open, so nothing above is mistaken for
more coverage than it has. This list previously called out several items
that this round of changes directly addresses — those are marked
**Resolved** below rather than deleted, so the history of what was found
and fixed stays visible instead of disappearing.

- **Resolved: 7z and cab are now unpacked** (see Archive recursion
  above), via the `sevenz-rust` and `cab` crates, same `GuardBudget`
  enforcement as zip/gzip/tar, with dedicated unit tests, `proptest`
  property tests, and `cargo-fuzz` targets. **RAR remains unsupported**,
  deliberately — see the Archive recursion section for why (no suitable
  permissively-licensed pure-Rust decoder).
- **Resolved: the fuzz harness now actually runs**, on a schedule, in CI
  (`fuzz-run` job) — see the Fuzzing section above. It could not be run
  from the sandboxed environment these harnesses were written in, but
  that's no longer the only place it can run: GitHub's runners have the
  network access a nightly toolchain needs. `proptest` property tests
  additionally run today, on every push, as a non-coverage-guided floor
  under that — and already caught a real panic bug in `sig-engine`'s
  hex-signature parser (UTF-8 char-boundary slicing on attacker-controlled
  pattern text), which is fixed.
- **Resolved (partially): the signature-update tool's full flow is now
  exercised end-to-end against a real local TLS server** (`rustls` +
  `rcgen`, a real handshake and record layer, not plain HTTP) — see
  Signature updates above. Writing that test also caught a real bug: the
  tool had `ureq`'s `rustls` feature enabled but not its `tls` feature, so
  it could not actually make an HTTPS request in production; that's
  fixed. Two concurrent/interrupted-update conditions are now covered too
  (real concurrent threads racing to swap into the same `sig_dir`; an
  update that fails before touching anything live). What's genuinely
  still open: a self-signed cert trusted explicitly in a test is not
  certificate-chain validation against the public WebPKI, and localhost
  is not a real network path with real latency/CDN behavior — running
  this against an actual production distribution point remains real
  follow-up work.
- **Resolved: the per-peer rate limiter and the metrics endpoint both now
  have dedicated load/fault-injection tests** — high-cardinality
  concurrent-peer churn and deterministic idle-eviction tests for the
  limiter (`limits.rs`); malformed/non-UTF-8/oversized-request and 200
  concurrent-connection tests for the metrics endpoint (`metrics.rs`).
  Writing the metrics tests surfaced a real gap: the endpoint had no read
  timeout, so a client that connected and sent nothing could hold its
  `tokio::spawn`'d task open indefinitely (a slow-loris-shaped gap, with
  no cap on how many such connections accumulate) — fixed with a 10s read
  timeout, covered by a dedicated test using a short timeout so the test
  itself stays fast.
- **Resolved: `--exclude-path` is now a real path prefix**, compared
  component-by-component via `Path::starts_with`, not a text/string
  prefix — excluding `/tmp` no longer also excludes the unrelated
  directory `/tmp2`. Covered by a regression test.
- **Resolved: quarantine neutralization is now ChaCha20-Poly1305 (a real
  AEAD stream cipher)**, not raw repeating-key XOR — see Real-time
  protection & quarantine above for what specifically improved (no
  known-plaintext keystream recovery; tamper-evidence via the Poly1305
  tag, exposed through a new `quarantine verify` subcommand). It is
  still, deliberately, not a confidentiality boundary against an operator
  with access to the quarantine store itself, since the key is stored
  right alongside the ciphertext for legitimate restore.
- **Resolved: `rclam-watch`'s auto-quarantine no longer re-reads the file
  from disk at quarantine time.** It now reads the file once
  (`Scanner::scan_in_memory`) and quarantines from that exact same buffer
  (`QuarantineManager::quarantine_bytes`) rather than scanning once and
  separately re-reading to quarantine — closing the TOCTOU window between
  "what was scanned" and "what was quarantined."
- **Windows now has real functional test coverage** of the TCP transport
  it uses exclusively (integration tests drive actual `TcpStream`
  connections through the full protocol handler, running on
  `windows-latest` in CI) — confirmed by an actual `cargo test --workspace`
  run on a real Windows machine after these changes (71 passed, 0
  failed), which is a meaningful step up from "compiles there." Nothing
  here is still a substitute for someone running `rclamd --port ...` (or
  `rclam-watch watch ...`, which is new since that Windows run) under real
  production load on Windows before depending on it there.
- **`rclam-watch` is a userspace on-access monitor, not a kernel
  minifilter.** There is an inherent window between a file being written
  and `rclam-watch` scanning it (bounded by `--debounce-ms` plus a fixed
  50ms settle delay) during which nothing prevents another process from
  reading or executing it — this is the same limitation every userspace
  real-time-protection agent has without a signed kernel driver, and is
  called out here rather than implied away. Nothing in this round of
  changes narrows this window further; doing so would mean shipping a
  signed kernel driver, a materially different (and materially riskier)
  project than a userspace agent.
