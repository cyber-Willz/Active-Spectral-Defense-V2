# spec_engine

CIC-IDS2018 × Spectral Graph Homology + HNSW security engine.

## Layout

```
Cargo.toml
src/
  main.rs                     — async entry point, calls spec_engine::run()
  lib.rs                      — QdrantSpectralSecurityEngine, CicRow, feature
                                 extraction, autoencoder, MITRE classifier,
                                 SpectralSecurityGraph (phantom-hub wrapper),
                                 synthetic CIC-IDS2018 dataset, run() pipeline
  l7_entropy.rs                — 12-dim L7 entropy/metadata feature block
  laplacian_regularizer.rs     — DynamicLaplacianRegularizer (online λ₂ bridging)
  spectral_homology.rs         — L_G vs L_HNSW spectral homology analysis,
                                 plus a polynomial-filter cross-check
                                 (`cross_check_ct_with_polynomial_filter`)
  jacobi_ds.rs                 — Jacobi orthogonal-polynomial basis: stable
                                 evaluation/differentiation, Gauss-Jacobi
                                 quadrature, and JacobiConv basis-conversion
  spectral_graph/
    mod.rs                     — module root / re-exports
    error.rs                   — GraphError
    graph.rs                   — adjacency-list Graph + BFS/Laplacian +
                                 laplacian_matvec (matrix-free L·v)
    embedding.rs                — Jacobi *eigenvalue-rotation* algorithm,
                                   SpectralEmbedding, phantom-hub bridging
    poly_filter.rs               — matrix-free polynomial approximation of
                                   L^+ built on jacobi_ds (see below)
    report.rs                   — GraphReport / PairwiseResult pretty-printer
```

## `jacobi_ds` and `spectral_graph::poly_filter`

`jacobi_ds` implements **Jacobi orthogonal polynomials** (basis evaluation,
Gauss-Jacobi quadrature, `JacobiConv` basis conversion) — a different
mathematical object from the **Jacobi eigenvalue rotation algorithm**
already used in `spectral_graph::embedding` to diagonalise the Laplacian.
They share a name, not a purpose, so `jacobi_ds` isn't a drop-in eigensolver
replacement.

What it does enable: `spectral_graph::poly_filter` uses `jacobi_ds`'s
Gauss-Jacobi quadrature to fit a degree-`d` Jacobi-polynomial approximation
`q(λ) ≈ 1/λ`, then evaluates `q(L) v` via the same three-term recurrence
`JacobiPoly::eval` uses — except each multiplication by the scalar
recurrence variable becomes a `Graph::laplacian_matvec` call instead. This
is the standard "polynomial graph filter" technique (ChebNet / GPR-GNN /
JacobiConv-style spectral filtering) and gives an `O(d·(n+m))`,
matrix-free approximate commute-time distance — versus `O(n^3)` for the
full Jacobi-rotation eigendecomposition that `SpectralEmbedding::embed`
already pays for, and which needs `JacobiConfig::relaxed()`'s 10x
iteration budget and a relative (not absolute) tolerance just to converge
on the denser `L_HNSW` graph.

It is **not** a replacement for `SpectralEmbedding`: Fiedler cosine
similarity and k-subspace alignment in `spectral_homology.rs` genuinely
need actual eigenvectors, which `poly_filter` never produces. What it adds
is `spectral_homology::cross_check_ct_with_polynomial_filter`, a cheap
self-consistency check — Spearman correlation between the exact
eigendecomposition's commute-time distances and the fast polynomial
approximation's — surfaced as an extra diagnostic line in Phase 6 of
`run()`. High correlation is evidence the `O(n^3)` solver actually
converged to something structurally sound, rather than merely satisfying
`JacobiConfig::relaxed()`'s relative-residual escape hatch while having
drifted on individual eigenvectors.

### Bug found and fixed: NaN silently laundered into a fake `0.0`

A first version of `poly_filter` sized the polynomial's fitted domain from
`estimate_lambda_max` (power iteration) alone. On the sample dataset's
hub-bridged `L_G`, power iteration underestimated the true spectral
radius, so the mapped Laplacian argument fell outside `[-1, 1]` for some
pairs and the degree-40 Chebyshev polynomial blew up to a non-finite
value. The code guarded the result with `quad.max(0.0)` — intended to
clamp harmless floating-point noise around zero — but **`f64::max` does
not propagate `NaN`**: `NaN.max(0.0)` evaluates to `0.0`, not `NaN`. Every
failed pair was silently reported as a plausible-looking commute-time
distance of `0.0`, which collapsed `cross_check_ct_with_polynomial_filter`'s
correlation to an exact `0.0` (zero variance in the approximate series,
not a `NaN`/"n/a") — observed in practice as a real run's Phase 6 printing
`ρ = 0.0000 ☆☆☆ investigate — possible non-convergence`.

Fixed by:
- `gershgorin_lambda_max` — a Gershgorin-circle-theorem upper bound
  (`λ_max(L) ≤ 2·max_degree`), exact and `O(n)`, with no convergence risk
  at all. This is now what sizes the polynomial filter's domain, both in
  `cross_check_ct_with_polynomial_filter` and in `poly_filter`'s own
  tests — `estimate_lambda_max` (power iteration) is kept as a separate,
  independently-tested utility, not as the domain source.
- `estimate_commute_time_distance` now checks `quad.is_finite()` *before*
  clamping and returns an explicit `Err` on failure, so a bad pair is
  skipped by the cross-check rather than injected as a fake `0.0`.
- Regression tests: `gershgorin_bound_is_a_valid_upper_bound_on_lambda_max`
  and `commute_time_distance_errors_on_undersized_domain_instead_of_returning_zero`
  in `poly_filter.rs`.

## Build

```
cargo build --locked
```

## Run (requires a local Qdrant instance)

```
docker run -p 6333:6333 -p 6334:6334 qdrant/qdrant
cargo run --locked
```

`run()` executes six phases: benign-baseline pretraining, pre-ingest spectral
topology, streaming ingestion with anomaly scoring + MITRE tagging, Qdrant
read-back evaluation, per-class detection-rate breakdown, and a Phase 6
spectral-homology comparison of the network graph (`L_G`) against the
HNSW k-NN projection graph (`L_HNSW`).

## Tests

```
cargo test --locked
```

Unit tests cover: L7 entropy dimensions (`l7_entropy.rs`), Jacobi/subspace
statistics helpers, and the spectral-homology verdict logic — including the
regression test that pins the verdict to NEGLIGIBLE when eigenvector
alignment is near-zero even though eigenvalue-sequence correlation is high
(`spectral_homology.rs::tests::verdict_ignores_high_eigenvalue_correlation_when_eigenvectors_disagree`).

Also: `jacobi_ds.rs`'s own test suite (polynomial evaluation, Gauss-Jacobi
quadrature exactness, `JacobiConv` round-trips); `graph.rs::tests::
laplacian_matvec_matches_dense_multiply` (matrix-free matvec vs. the dense
`laplacian()`); `poly_filter.rs`'s tests (power-iteration `lambda_max`
vs. the exact top eigenvalue, the Gershgorin bound's validity, polynomial-
filter commute-time distance vs. `SpectralEmbedding::geometric_distance`,
linearity of `apply`, and the regression test pinning an undersized
spectral domain to an `Err` rather than a silently-wrong `0.0`); and
`spectral_homology.rs::tests::poly_filter_cross_check_agrees_with_exact_embedding`.

## Bugs found and fixed in this pass (verified against a real Rust 1.75
## toolchain, not by inspection)

This pass installed `rustc`/`cargo` 1.75 (matching the crate's stated MSRV
pin) and actually compiled and ran the isolated, dependency-light modules
(`jacobi_ds.rs`, `spectral_graph/*`, `spectral_homology.rs`,
`laplacian_regularizer.rs` — everything except `lib.rs` and
`l7_entropy.rs`, which need `burn`/`qdrant-client`/`tokio`/`CicRow` and
weren't exercised). Four real problems surfaced:

1. **`Cargo.toml` declared `edition = "2024"` while every other document
   in this archive states the crate is pinned to Rust 1.75.** Edition 2024
   wasn't stabilized until Rust 1.85 — `cargo build` fails immediately
   (`feature 'edition2024' is required`) on the toolchain the crate
   claims to target. Fixed to `edition = "2021"`, which every module here
   compiles under cleanly and needs nothing newer than 1.75 provides
   (no `let-else` chains, no 2024-only capture/dyn rules in use).
2. **`jacobi_norm_squared(0, alpha, beta)` returned `NaN`** whenever
   `alpha + beta = -1` (the Chebyshev weight used throughout
   `poly_filter.rs`) — the same singularity described below for the
   Gershgorin-bound work, still present unfixed in this snapshot. Traced,
   reproduced, and fixed the same way: special-case `n = 0` with its own
   finite closed form (`h_0 = 2^(a+b+1) * Gamma(a+1) * Gamma(b+1) /
   Gamma(a+b+2)`, no pole) instead of the general recurrence's
   `1/(2n+a+b+1)` term, which degenerates to `1/0` only at `n=0`.
   This was silently poisoning every `ResolventFilter::fit` call and
   caused 3 of 4 failures observed when the existing test suite was
   actually run (`apply_is_linear_in_the_input_vector`,
   `resolvent_commute_time_matches_exact_geometric_distance`,
   `poly_filter_cross_check_agrees_with_exact_embedding`).
3. **`homology_self_analysis_is_perfect`'s "ideal" feature fixture used
   the full eigenvector matrix as node features** — mathematically
   guaranteed degenerate (every pairwise distance between rows of a
   square orthogonal matrix is identically `sqrt(2)`), making the
   resulting k-NN graph arbitrary. Fixed to use the two leading
   non-trivial eigenvectors (empirically swept dims=1..5, skip=0..1,
   k=1..3 against this exact fixture; 2 non-trivial dims at the test's
   existing `k=2` gives `fiedler_cosine ~= 0.98`, comfortably clearing the
   `> 0.5` assertion, while higher dims start reintroducing spurious
   near-ties between non-adjacent path nodes).
4. **The undersized-domain guard only caught `NaN`/`Inf`, not merely
   astronomically large finite values.** A degree-40 Chebyshev polynomial
   evaluated just outside `[-1, 1]` grows exponentially but doesn't
   reliably overflow to `Inf` in `f64` — an undersized domain on a
   20-node path graph produced `~2e36`, which is finite and sailed past
   `!quad.is_finite()`, so `commute_time_distance_errors_on_undersized_
   domain_instead_of_returning_zero` failed (`got Ok(1.99e36)`, expected
   `Err`) once bug 2's fix stopped it from being masked by a NaN instead.
   Fixed by checking the domain analytically up front — comparing the
   caller's `lambda_max` against `gershgorin_lambda_max(graph)`, a cheap
   `O(n)` *guaranteed* upper bound with no iteration or convergence risk
   — rather than waiting to see whether the polynomial happens to blow up
   to something IEEE-754 classifies as non-finite.

**Result: 30/30 tests pass** in the isolated crate (26 pre-existing + 4
new/updated regression tests from the Gershgorin work below), verified by
actually running `cargo test`, not asserted. The full `spec_engine` crate
(this archive) was not built end-to-end: its `Cargo.toml` pulls `burn`,
`qdrant-client`, `tokio` (full), `reqwest`, and `hnsw_rs`, and this
sandbox's network egress allowlist doesn't include `static.rust-lang.org`/
`rustup`, so a newer toolchain couldn't be installed and today's
crates.io-latest versions of those dependencies (which now pull
transitive crates requiring edition 2024 themselves, e.g. `burn-dataset`
→ `image` → `ravif` → `rav1e` → `built 0.8`) couldn't be fully resolved
against 1.75 either. If you build this on a machine with a current
toolchain, the `edition = "2021"` fix above is unaffected either way —
2021 has been supported by every Rust release since 1.56.

## Note on Cargo.toml versions

Dependency versions in `Cargo.toml` are carried over verbatim from the
existing workspace configuration and were not individually re-verified
against crates.io beyond what's described above. Run `cargo build
--locked` in an environment with a current Rust toolchain and full
network access to verify and pull the exact pinned dependency versions.
