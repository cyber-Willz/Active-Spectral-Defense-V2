# Fuzz targets

`cargo-fuzz` scaffold covering the eight parsers in this codebase that
consume fully attacker-controlled bytes: PE headers, `.ndb`/`.hdb`
signature definitions, and the zip/gzip/tar/7z/cab archive extractors.

## Status: built AND scheduled to actually run in CI

Every target here compiles and type-checks against the current crate APIs.
As of this change, `.github/workflows/ci.yml` also has a `fuzz-run` job
that executes real coverage-guided fuzzing (`cargo fuzz run <target> --
-max_total_time=120`) for every target, on a daily schedule and on manual
`workflow_dispatch` -- not just a build sanity-check. A crash produces an
uploaded artifact (the failing input) rather than only a red CI run.

That job could not be exercised from the sandboxed environment several of
these targets (and the 7z/cab targets specifically) were added from: no
network path to `static.rust-lang.org`/`sh.rustup.rs` meant no nightly
toolchain, and `cargo-fuzz` needs one. GitHub's own runners have full
internet access, so the CI job genuinely runs there -- this isn't a
workaround, it's the intended long-term home for this regardless of where
any given target was authored.

In the meantime, `proptest`-based property tests living directly in
`archive-guard`, `pe-analyze`, and `sig-engine`'s own `#[cfg(test)] mod
proptests` (run by plain `cargo test`, on stable, on every push) cover the
same "never panic on adversarial input" property for these same functions.
They're not a replacement for coverage-guided fuzzing -- proptest doesn't
evolve a corpus based on code coverage the way libFuzzer does -- but they
run today, on every commit, and already found and fixed one real bug this
way (a UTF-8 char-boundary panic in `sig-engine`'s hex-signature parser,
`HexSignature::parse` -- see git history / the `proptest-regressions`
seed file checked in alongside `sig-engine/src/hexsig.rs`).

## Running locally

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run fuzz_zip_extract
cargo +nightly fuzz run fuzz_gzip_extract
cargo +nightly fuzz run fuzz_tar_extract
cargo +nightly fuzz run fuzz_7z_extract
cargo +nightly fuzz run fuzz_cab_extract
cargo +nightly fuzz run fuzz_pe_parse
cargo +nightly fuzz run fuzz_hexsig_ndb
cargo +nightly fuzz run fuzz_hashdb
```

## Why these eight

- `fuzz_pe_parse` -- the PE header parser has the most internal
  offsets/lengths taken directly from attacker bytes (DOS stub, PE
  signature offset, section table) of anything in this codebase.
- `fuzz_zip_extract` / `fuzz_gzip_extract` / `fuzz_tar_extract` /
  `fuzz_7z_extract` / `fuzz_cab_extract` -- exercise the archive-bomb
  guards (`GuardBudget`) against malformed/adversarial input directly,
  rather than only the hand-crafted bombs in the unit tests. The invariant
  under test is "never panics, never reads/allocates past what the budget
  allows" -- errors are an expected, fine outcome. The 7z and cab targets
  additionally exercise two third-party decoder crates (`sevenz-rust`,
  `cab`) this codebase doesn't control the internals of, which is exactly
  the kind of dependency worth fuzzing rather than just trusting.
- `fuzz_hexsig_ndb` / `fuzz_hashdb` -- signature files are normally
  operator-supplied rather than attacker-controlled, but a panic while
  loading signatures at startup would take the whole daemon down, so the
  parser is still worth the scrutiny. (This is also where the proptest
  suite already found a real panic -- see above.)

This is a detached `cargo-fuzz`-style workspace (see the empty `[workspace]`
table in `Cargo.toml`) so it isn't swept into the parent workspace's
dependency resolution -- several parent crates pin exact dependency
versions for reasons unrelated to what `libfuzzer-sys` needs.
