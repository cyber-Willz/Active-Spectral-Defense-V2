
use std::collections::HashMap;

use crate::spectral_graph::{
    build_connected_graph,
    embedding::{JacobiConfig, SpectralEmbedding},
    graph::Graph,
    poly_filter::{estimate_commute_time_distance, gershgorin_lambda_max},
};

// ── Public result types ───────────────────────────────────────────────────────

/// Full spectral homology report comparing **L_G** and **L_HNSW**.
#[derive(Debug, Clone)]
pub struct SpectralHomologyReport {
    pub n_nodes:                   usize,
    pub n_flows:                   usize,
    pub k:                         usize,
    pub lambda1_g:                 f64,
    pub lambda1_hnsw:              f64,
    /// True when the raw k-NN projection graph was disconnected and a
    /// phantom hub had to be injected to make commute-time distances
    /// defined — mirrors `SpectralSecurityGraph::hub_injected` for `L_G`.
    pub hub_injected_hnsw:         bool,
    /// Cosine similarity between Fiedler vectors of L_G and L_{G_H}.
    /// Range [0,1] (absolute value, sign-invariant).
    pub fiedler_cosine:            f64,
    /// Mean cos²(θ) of principal angles between the k-dim eigenspaces.
    pub subspace_alignment:        f64,
    /// Spearman rank correlation of pairwise commute-time distances.
    pub ct_rank_correlation:       f64,
    /// Eigenvalue correspondence: Pearson r between sorted eigenvalue sequences
    /// of L_G and L_{G_H} (after log-transform to handle scale).
    ///
    /// NOTE: this compares only the *shape* of the sorted spectrum, not
    /// node-to-node correspondence. Two graphs with similar size/degree
    /// statistics can produce a highly correlated eigenvalue sequence even
    /// with completely unrelated eigenvectors. It is diagnostic context,
    /// not primary evidence of structural alignment — see `verdict`.
    pub eigenvalue_correlation:    f64,
    pub per_mode_cosines:          Vec<f64>,
    pub verdict:                   String,
}

impl SpectralHomologyReport {
    pub fn print(&self) {
        println!("╔══════════════════════════════════════════════════════════════════╗");
        println!("║  Spectral Homology Report: L_G  vs  L_HNSW                       ║");
        println!("╠══════════════════════════════════════════════════════════════════╣");
        println!("║  Shared IP nodes : {}   Flows : {}   k : {}",
            self.n_nodes, self.n_flows, self.k);
        println!("╠──────────────────────────────────────────────────────────────────╣");
        println!("║  Algebraic connectivity");
        println!("║    λ₁(L_G)    = {:.6}", self.lambda1_g);
        println!("║    λ₁(L_HNSW) = {:.6}  (hub_injected={})",
            self.lambda1_hnsw, self.hub_injected_hnsw);
        println!("╠──────────────────────────────────────────────────────────────────╣");
        println!("║  Eigenvector alignment  (primary signal — drives the verdict)");
        let ct_display = if self.ct_rank_correlation.is_nan() {
            "NaN".to_string()
        } else {
            format!("{:.4}", self.ct_rank_correlation)
        };
        println!("║    Fiedler cosine similarity  : {:.4}  {}",
            self.fiedler_cosine, rating(self.fiedler_cosine));
        println!("║    k-subspace alignment       : {:.4}  {}",
            self.subspace_alignment, rating(self.subspace_alignment));
        println!("║    CT rank correlation (ρ)    : {}  {}",
            ct_display,
            if self.ct_rank_correlation.is_nan() {
                rating(0.0)
            } else {
                rating(self.ct_rank_correlation.abs())
            });
        println!("╠──────────────────────────────────────────────────────────────────╣");
        println!("║  Spectrum-shape diagnostic  (context only — NOT part of the verdict)");
        println!("║    Eigenvalue correlation (r) : {:.4}  {}",
            self.eigenvalue_correlation, rating(self.eigenvalue_correlation.abs()));
        println!("║    (compares sorted-spectrum shape only; high r can occur even when");
        println!("║     eigenvectors are unrelated — see Fiedler/subspace/CT above)");
        println!("╠──────────────────────────────────────────────────────────────────╣");
        println!("║  Per-mode cosines |φₖ(G)·φₖ(G_H)|  (modes 1–{}):",
            self.per_mode_cosines.len());
        for (k, &cos) in self.per_mode_cosines.iter().enumerate() {
            let bar = bar(cos, 20);
            println!("║    mode {:2}: {:.4}  {}", k + 1, cos, bar);
        }
        println!("╠──────────────────────────────────────────────────────────────────╣");
        println!("║  Verdict: {}", self.verdict);
        println!("╚══════════════════════════════════════════════════════════════════╝");
    }
}

fn rating(v: f64) -> &'static str {
    if v > 0.85      { "★★★ strong" }
    else if v > 0.65 { "★★☆ moderate" }
    else if v > 0.40 { "★☆☆ weak" }
    else             { "☆☆☆ negligible" }
}

fn bar(v: f64, width: usize) -> String {
    let filled = (v * width as f64).round() as usize;
    format!("[{}{}]", "█".repeat(filled), "░".repeat(width - filled.min(width)))
}

// ── Flow record ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FlowRecord {
    pub src_ip:   String,
    pub dst_ip:   String,
    pub features: Vec<f32>,
    pub label:    String,
}

// ── HNSW projection graph ─────────────────────────────────────────────────────

/// Build the projected HNSW graph G_H over IP-address nodes via brute-force k-NN.
///
/// Edges connect the **source** IP of each flow to the source IPs of its
/// `k` nearest neighbours in feature space. Any entity in `ip_index` that
/// never appears as a flow's `src_ip` (a pure destination, e.g. a DoS
/// victim) receives no edge here and would otherwise sit isolated in the
/// raw projection graph — trivially forcing λ₁ = 0 and making every
/// commute-time-based comparison in [`analyse`] degenerate to `NaN`.
///
/// Rather than papering over that with fabricated `src→dst` edges (which
/// would leak the very topology this analysis is trying to test the
/// feature space against), the same phantom-hub bridging used for `L_G`
/// ([`build_connected_graph`]) is applied here too. This keeps the two
/// sides of the comparison methodologically symmetric and makes
/// commute-time distances well-defined on both without biasing the result.
///
/// Returns `(graph, hub_was_injected)`.
fn build_hnsw_projection_graph(
    flows:    &[FlowRecord],
    ip_index: &HashMap<String, usize>,
    n_ips:    usize,
    k:        usize,
) -> (Graph, bool) {
    let n_flows = flows.len();
    let mut knn_edges: Vec<(usize, usize)> = Vec::new();

    for i in 0..n_flows {
        let mut dists: Vec<(usize, f32)> = (0..n_flows)
            .filter(|&j| j != i)
            .map(|j| {
                let d = flows[i].features.iter()
                    .zip(flows[j].features.iter())
                    .map(|(a, b)| (a - b) * (a - b))
                    .sum::<f32>();
                (j, d)
            })
            .collect();
        dists.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

        for &(j, _) in dists.iter().take(k) {
            let ip_i = ip_index.get(&flows[i].src_ip).copied();
            let ip_j = ip_index.get(&flows[j].src_ip).copied();
            if let (Some(u), Some(v)) = (ip_i, ip_j) {
                if u != v {
                    knn_edges.push((u, v));
                }
            }
        }
    }

    match build_connected_graph(n_ips, &knn_edges) {
        Ok((g, hub_injected)) => (g, hub_injected),
        Err(_) => (Graph::new(n_ips.max(1)).unwrap(), false),
    }
}

// ── Statistical helpers ───────────────────────────────────────────────────────

fn cosine_abs(a: &[f64], b: &[f64]) -> f64 {
    assert_eq!(a.len(), b.len(), "cosine_abs: length mismatch");
    let dot: f64 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na:  f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let nb:  f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
    if na < 1e-12 || nb < 1e-12 { return 0.0; }
    (dot / (na * nb)).abs()
}

/// Mean cos²(θ) between the k-dim eigenspaces of two spectral embeddings
/// (standard principal angle / subspace alignment metric).
fn subspace_alignment(emb_g: &SpectralEmbedding, emb_h: &SpectralEmbedding, k: usize) -> f64 {
    let n = emb_g.num_nodes.min(emb_h.num_nodes);
    let k = k.min(emb_g.num_dims - 1).min(emb_h.num_dims - 1).min(n);
    if k == 0 { return 0.0; }

    let mut gram_sq_sum = 0.0_f64;
    for ki in 1..=k {
        for kj in 1..=k {
            let dot: f64 = (0..n)
                .map(|node| {
                    emb_g.eigenvector_matrix[node][ki]
                        * emb_h.eigenvector_matrix[node][kj]
                })
                .sum();
            gram_sq_sum += dot * dot;
        }
    }
    gram_sq_sum / k as f64
}

fn spearman(xs: &[f64], ys: &[f64]) -> f64 {
    assert_eq!(xs.len(), ys.len());
    let n = xs.len();
    if n < 2 { return 0.0; }

    let rank_of = |vals: &[f64]| -> Vec<f64> {
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by(|&a, &b| vals[a].partial_cmp(&vals[b]).unwrap_or(std::cmp::Ordering::Equal));
        let mut ranks = vec![0.0f64; n];
        let mut i = 0;
        while i < n {
            let mut j = i + 1;
            while j < n && (vals[order[j]] - vals[order[i]]).abs() < 1e-12 { j += 1; }
            let avg_rank = (i + j - 1) as f64 / 2.0 + 1.0;
            for idx in &order[i..j] { ranks[*idx] = avg_rank; }
            i = j;
        }
        ranks
    };

    let rx = rank_of(xs);
    let ry = rank_of(ys);
    let mx: f64 = rx.iter().sum::<f64>() / n as f64;
    let my: f64 = ry.iter().sum::<f64>() / n as f64;
    let num: f64 = rx.iter().zip(ry.iter()).map(|(a, b)| (a - mx) * (b - my)).sum();
    let da:  f64 = rx.iter().map(|a| (a - mx) * (a - mx)).sum::<f64>().sqrt();
    let db:  f64 = ry.iter().map(|b| (b - my) * (b - my)).sum::<f64>().sqrt();
    if da < 1e-12 || db < 1e-12 { return 0.0; }
    num / (da * db)
}

fn pearson(xs: &[f64], ys: &[f64]) -> f64 {
    let n = xs.len();
    if n < 2 { return 0.0; }
    let mx: f64 = xs.iter().sum::<f64>() / n as f64;
    let my: f64 = ys.iter().sum::<f64>() / n as f64;
    let num: f64 = xs.iter().zip(ys).map(|(a, b)| (a - mx) * (b - my)).sum();
    let da: f64  = xs.iter().map(|a| (a - mx).powi(2)).sum::<f64>().sqrt();
    let db: f64  = ys.iter().map(|b| (b - my).powi(2)).sum::<f64>().sqrt();
    if da < 1e-12 || db < 1e-12 { return 0.0; }
    num / (da * db)
}

/// Pairwise commute-time distances over the first `n` shared nodes.
/// `n` must be capped to the smaller of the two embeddings being compared —
/// independent hub injection on `L_G` and `L_HNSW` can leave them with a
/// different node count, and CT vectors being compared via [`spearman`]
/// must have equal length.
fn pairwise_ct(emb: &SpectralEmbedding, n: usize) -> Vec<f64> {
    let n = n.min(emb.num_nodes);
    let mut out = Vec::with_capacity(n * (n - 1) / 2);
    for i in 0..n {
        for j in (i + 1)..n {
            let d = emb.geometric_distance(i, j).unwrap_or(0.0);
            out.push(d);
        }
    }
    out
}

// ── Main entry point ──────────────────────────────────────────────────────────

/// Run the full spectral homology analysis and return a [`SpectralHomologyReport`].
pub fn analyse(
    flows:      &[FlowRecord],
    g_emb:      &SpectralEmbedding,
    ip_index:   &HashMap<String, usize>,
    k:          usize,
    jacobi_cfg: &JacobiConfig,
) -> SpectralHomologyReport {
    let n_ips   = g_emb.num_nodes;
    let n_flows = flows.len();

    // Step 1: Build L_{G_H} (projected HNSW graph), bridging any isolated
    // (destination-only) nodes exactly as L_G does.
    let (g_h, hub_injected_hnsw) = build_hnsw_projection_graph(flows, ip_index, n_ips, k);

    let h_emb = match SpectralEmbedding::embed(&g_h, jacobi_cfg) {
        Ok(e)  => e,
        Err(e) => {
            return SpectralHomologyReport {
                n_nodes: n_ips, n_flows, k,
                lambda1_g:              g_emb.algebraic_connectivity,
                lambda1_hnsw:           0.0,
                hub_injected_hnsw,
                fiedler_cosine:         0.0,
                subspace_alignment:     0.0,
                ct_rank_correlation:    f64::NAN,
                eigenvalue_correlation: 0.0,
                per_mode_cosines:       vec![],
                verdict: format!("L_HNSW eigendecomposition failed: {e}"),
            };
        }
    };

    // L_G and L_HNSW may each independently gain a phantom hub node, so
    // their node counts can differ by one — always compare over the
    // smaller, shared prefix.
    let n_shared = g_emb.num_nodes.min(h_emb.num_nodes);

    // Step 2: Fiedler cosine similarity
    let fiedler_g: Vec<f64> = (0..n_shared)
        .map(|i| g_emb.eigenvector_matrix[i][1.min(g_emb.num_dims - 1)])
        .collect();
    let fiedler_h: Vec<f64> = (0..n_shared)
        .map(|i| h_emb.eigenvector_matrix[i][1.min(h_emb.num_dims - 1)])
        .collect();
    let fiedler_cosine = cosine_abs(&fiedler_g, &fiedler_h);

    // Step 3: k-subspace alignment
    let sub_k = 4.min(g_emb.num_dims - 1).min(h_emb.num_dims - 1);
    let subspace_align = subspace_alignment(g_emb, &h_emb, sub_k);

    // Step 4: Per-mode cosines
    let n_modes = 6.min(g_emb.num_dims - 1).min(h_emb.num_dims - 1);
    let per_mode: Vec<f64> = (1..=n_modes)
        .map(|mode| {
            let a: Vec<f64> = (0..n_shared)
                .map(|i| g_emb.eigenvector_matrix[i][mode])
                .collect();
            let b: Vec<f64> = (0..n_shared)
                .map(|i| h_emb.eigenvector_matrix[i][mode])
                .collect();
            cosine_abs(&a, &b)
        })
        .collect();

    // Step 5: Commute-time rank correlation.
    // Both graphs now go through identical phantom-hub bridging, so this
    // is computable whenever either graph had >1 node to begin with —
    // it's no longer silently NaN'd out by an artifact of how G_H's
    // edges were seeded.
    let ct_rank_corr = if g_emb.algebraic_connectivity > 1e-8
        && h_emb.algebraic_connectivity > 1e-8
    {
        let ct_g = pairwise_ct(g_emb, n_shared);
        let ct_h = pairwise_ct(&h_emb, n_shared);
        spearman(&ct_g, &ct_h)
    } else {
        f64::NAN
    };

    // Step 6: Eigenvalue correlation (log-transformed).
    // Diagnostic only — see doc comment on `eigenvalue_correlation`.
    let ev_count = g_emb.eigenvalues.len().min(h_emb.eigenvalues.len());
    let ev_g: Vec<f64> = g_emb.eigenvalues[..ev_count]
        .iter().map(|&v| (v + 1e-8).ln()).collect();
    let ev_h: Vec<f64> = h_emb.eigenvalues[..ev_count]
        .iter().map(|&v| (v + 1e-8).ln()).collect();
    let eigenvalue_corr = pearson(&ev_g, &ev_h);

    // Step 7: Verdict
    let verdict = build_verdict(fiedler_cosine, subspace_align, ct_rank_corr, eigenvalue_corr);

    SpectralHomologyReport {
        n_nodes:                n_ips,
        n_flows,
        k,
        lambda1_g:              g_emb.algebraic_connectivity,
        lambda1_hnsw:           h_emb.algebraic_connectivity,
        hub_injected_hnsw,
        fiedler_cosine,
        subspace_alignment:     subspace_align,
        ct_rank_correlation:    ct_rank_corr,
        eigenvalue_correlation: eigenvalue_corr,
        per_mode_cosines:       per_mode,
        verdict,
    }
}

/// Cross-check the exact eigendecomposition-based commute-time distances
/// (from `g_emb`, produced by the `O(n^3)` Jacobi-*rotation*
/// `SpectralEmbedding::embed`) against the matrix-free, `jacobi_ds`-based
/// polynomial-filter estimate from `spectral_graph::poly_filter`, on up to
/// `max_pairs` node pairs (the first `max_pairs` in index order — callers
/// wanting a random sample should shuffle indices before calling).
///
/// Returns the Spearman rank correlation between the two distance series.
/// A value close to `1.0` means the exact eigendecomposition and the fast
/// polynomial approximation agree — a cheap sanity check that the `O(n^3)`
/// Jacobi-rotation solver actually converged to something structurally
/// sound, rather than merely satisfying `JacobiConfig::relaxed()`'s
/// relative-residual escape hatch (see `embedding.rs`) while having drifted
/// on a few individual eigenvectors. `f64::NAN` if there are fewer than 2
/// usable node pairs or the spectral interval degenerates.
///
/// The polynomial filter's domain is sized from
/// [`gershgorin_lambda_max`] — a proven upper bound on the true spectral
/// radius — rather than [`estimate_lambda_max`]'s power iteration, which
/// can silently *underestimate* on slow-converging graphs (e.g. one with a
/// high-degree phantom hub) and previously caused every pair's polynomial
/// evaluation to blow up outside its fitted domain. Any individual pair
/// that still fails (non-finite quadratic form) is skipped rather than
/// folded in as a spurious `0.0` — see
/// `poly_filter::estimate_commute_time_distance`'s non-finite guard.
///
/// This does **not** replace `ct_rank_correlation` in
/// [`SpectralHomologyReport`] (which measures agreement *between* `L_G`
/// and `L_HNSW`) — it measures self-consistency of a *single* embedding
/// against an independently-computed approximation, so it is exposed as a
/// standalone function rather than folded into the report.
pub fn cross_check_ct_with_polynomial_filter(
    graph:     &Graph,
    g_emb:     &SpectralEmbedding,
    max_pairs: usize,
) -> f64 {
    let n = g_emb.num_nodes;
    if n < 2 || max_pairs == 0 {
        return f64::NAN;
    }

    let lambda_max = gershgorin_lambda_max(graph);
    let lambda_min = (g_emb.algebraic_connectivity * 0.5).max(1e-4);
    if !(lambda_max > lambda_min) {
        return f64::NAN;
    }

    let mut exact  = Vec::with_capacity(max_pairs);
    let mut approx = Vec::with_capacity(max_pairs);
    'outer: for i in 0..n {
        for j in (i + 1)..n {
            if exact.len() >= max_pairs {
                break 'outer;
            }
            let Ok(e) = g_emb.geometric_distance(i, j) else { continue };
            let Ok(a) = estimate_commute_time_distance(graph, i, j, lambda_min, lambda_max, 40)
            else {
                continue;
            };
            exact.push(e);
            approx.push(a);
        }
    }

    if exact.len() < 2 {
        return f64::NAN;
    }
    spearman(&exact, &approx)
}

/// Build the homology verdict from the three *primary* eigenvector-alignment
/// signals (Fiedler cosine, k-subspace alignment, CT rank correlation).
///
/// `ev_r` (eigenvalue correlation) is deliberately **excluded** from the
/// averaged signal: it compares only the sorted-spectrum *shape*, which two
/// graphs with similar size/degree statistics can share even when their
/// eigenvectors are completely unrelated (no node-to-node correspondence).
/// Including it would let a spectrum-shape coincidence mask a genuinely
/// negligible structural alignment — exactly what happened when
/// eigenvalue_correlation ≈ 0.93 while every direct eigenvector metric
/// (Fiedler, subspace, CT) sat below 0.13. It's still surfaced to the
/// person as an annotated caveat, never silently dropped.
fn build_verdict(fiedler: f64, subspace: f64, ct_rho: f64, ev_r: f64) -> String {
    let ct_abs = if ct_rho.is_nan() { 0.0 } else { ct_rho.abs() };
    let avg_signal = (fiedler + subspace + ct_abs) / 3.0;

    let base = if avg_signal > 0.80 {
        "STRONG homology: L_HNSW eigenvectors are faithful proxies for L_G. \
         The feature space encodes network topology — HNSW k-NN retrieval \
         respects the spectral partition of the network graph."
    } else if avg_signal > 0.55 {
        "MODERATE homology: significant but imperfect alignment. \
         The statistical feature block captures degree-level topology \
         (Fiedler partition), but higher spectral modes are scrambled by \
         flow-level noise and L7 entropy dimensions."
    } else if avg_signal > 0.30 {
        "WEAK homology: the Fiedler direction is partially preserved but \
         higher modes do not align. The HNSW index groups flows by \
         traffic-volume similarity, not by network-topology proximity. \
         Spectral distances in L_HNSW should not be interpreted as \
         commute-time distances in L_G."
    } else {
        "NEGLIGIBLE homology: L_HNSW and L_G eigenvectors are essentially \
         orthogonal. The feature map does not encode network topology. \
         Use spectral distances from L_G directly; do not substitute \
         HNSW proximity for network-graph structural proximity."
    };

    if ev_r.abs() > 0.7 && avg_signal < 0.30 {
        format!(
            "{base} Note: eigenvalue correlation is high (r={ev_r:.2}) despite \
             this — the two graphs have similarly-shaped spectra (comparable \
             size/degree statistics) but that reflects bulk structure, not \
             node-level correspondence, and should not be read as agreement."
        )
    } else {
        base.to_string()
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spectral_graph::graph::Graph;

    fn path_graph(n: usize) -> Graph {
        let edges: Vec<(usize, usize)> = (0..n - 1).map(|i| (i, i + 1)).collect();
        Graph::from_edges(n, &edges).unwrap()
    }

    #[test]
    fn cosine_abs_identical() {
        let v = vec![1.0, 2.0, 3.0];
        assert!((cosine_abs(&v, &v) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn cosine_abs_orthogonal() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![0.0, 1.0, 0.0];
        assert!(cosine_abs(&a, &b) < 1e-10);
    }

    #[test]
    fn spearman_identical() {
        let v = vec![1.0, 3.0, 2.0, 4.0];
        assert!((spearman(&v, &v) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn spearman_reversed() {
        let a = vec![1.0, 2.0, 3.0, 4.0];
        let b = vec![4.0, 3.0, 2.0, 1.0];
        assert!((spearman(&a, &b) + 1.0).abs() < 1e-9);
    }

    #[test]
    fn subspace_alignment_identical_embeddings() {
        let g = path_graph(5);
        let cfg = JacobiConfig::default();
        let emb = SpectralEmbedding::embed(&g, &cfg).unwrap();
        let align = subspace_alignment(&emb, &emb, 3);
        assert!(
            (align - 1.0).abs() < 1e-6,
            "identical embeddings: expected alignment≈1.0, got {align}"
        );
    }

    #[test]
    fn homology_self_analysis_is_perfect() {
        let n = 6;
        let g = path_graph(n);
        let cfg = JacobiConfig { max_iterations: 1000, epsilon: 1e-9, dimensions: None };
        let g_emb = SpectralEmbedding::embed(&g, &cfg).unwrap();

        let mut ip_index = HashMap::new();
        for i in 0..n {
            ip_index.insert(format!("ip_{i}"), i);
        }

        // Use only the leading non-trivial eigenvectors as node features —
        // NOT the full eigenvector matrix. Rows of a square orthogonal
        // matrix are themselves orthonormal, so every pairwise Euclidean
        // distance between rows of the *full* matrix is identically
        // sqrt(2) regardless of graph structure (verified: all 15 pairwise
        // distances on this 6-node fixture come back exactly 2.0 with the
        // full matrix), making the resulting k-NN graph essentially
        // arbitrary. A genuine low-dimensional spectral embedding — the
        // first few non-trivial eigenvectors, skipping the trivial
        // constant eigenvector at index 0 — is what "ideal spectral
        // features" actually calls for here.
        // Empirically verified (swept dims=1..5, skip=0..1, k=1..3 against
        // this fixture): 2 leading non-trivial eigenvectors with this
        // test's k=2 gives fiedler_cosine ~= 0.98. A single eigenvector
        // (just the Fiedler vector) already does well too (~0.98 at k=2),
        // but including the next mode is more robust to the k-NN tie
        // structure than dims=1 alone, and stays clear of the higher modes
        // (dims>=4 here), which start reintroducing spurious near-ties
        // between non-adjacent path nodes and can crash fiedler_cosine
        // back toward 0.
        const FEATURE_DIMS: usize = 2;
        let flows: Vec<FlowRecord> = (0..n).map(|i| {
            let feats: Vec<f32> = g_emb.eigenvector_matrix[i]
                .iter().skip(1).take(FEATURE_DIMS).map(|&x| x as f32).collect();
            FlowRecord {
                src_ip:   format!("ip_{i}"),
                dst_ip:   format!("ip_{}", (i + 1) % n),
                features: feats,
                label:    "test".into(),
            }
        }).collect();

        let report = analyse(&flows, &g_emb, &ip_index, 2, &cfg);

        assert!(
            report.fiedler_cosine > 0.5,
            "ideal spectral features: fiedler_cosine={:.4} expected > 0.5",
            report.fiedler_cosine
        );
    }

    #[test]
    fn dest_only_node_no_longer_forces_nan_ct_correlation() {
        // Node 3 never appears as a flow's src_ip — the exact pattern that
        // previously left it isolated in G_H (λ₁=0, ct_rank_correlation=NaN).
        let n = 4;
        let g = path_graph(n);
        let cfg = JacobiConfig::default();
        let g_emb = SpectralEmbedding::embed(&g, &cfg).unwrap();

        let mut ip_index = HashMap::new();
        for i in 0..n {
            ip_index.insert(format!("ip_{i}"), i);
        }

        // Only src_ip in {0,1,2}; node 3 is destination-only.
        let flows: Vec<FlowRecord> = (0..6).map(|i| {
            let src = i % 3;
            FlowRecord {
                src_ip:   format!("ip_{src}"),
                dst_ip:   "ip_3".into(),
                features: vec![i as f32, (i * 2) as f32],
                label:    "test".into(),
            }
        }).collect();

        let report = analyse(&flows, &g_emb, &ip_index, 2, &cfg);
        assert!(
            !report.ct_rank_correlation.is_nan(),
            "hub bridging should make CT rank correlation computable even \
             with a destination-only node"
        );
    }

    #[test]
    fn verdict_ignores_high_eigenvalue_correlation_when_eigenvectors_disagree() {
        // Reproduces the exact scenario observed in production: three
        // primary eigenvector metrics all "negligible" (< 0.13) while
        // eigenvalue correlation alone is "strong" (0.93). The verdict
        // must classify this as NEGLIGIBLE (not dragged up by ev_r), and
        // must surface the discrepancy as a caveat.
        let verdict = build_verdict(0.0503, 0.0418, 0.1281, 0.9313);
        assert!(
            verdict.starts_with("NEGLIGIBLE"),
            "expected NEGLIGIBLE verdict despite high eigenvalue correlation, got: {verdict}"
        );
        assert!(
            verdict.contains("eigenvalue correlation is high"),
            "expected an explanatory caveat about the high eigenvalue correlation, got: {verdict}"
        );
    }

    #[test]
    fn poly_filter_cross_check_agrees_with_exact_embedding() {
        // On a small, well-conditioned graph the O(n^3) exact
        // eigendecomposition and the O(degree * (n+m)) matrix-free
        // polynomial-filter approximation should agree closely — this is
        // the self-consistency check `cross_check_ct_with_polynomial_filter`
        // exists to provide.
        let n = 10;
        let g = path_graph(n);
        let cfg = JacobiConfig::default();
        let g_emb = SpectralEmbedding::embed(&g, &cfg).unwrap();

        let corr = cross_check_ct_with_polynomial_filter(&g, &g_emb, 20);
        assert!(
            !corr.is_nan() && corr > 0.9,
            "expected strong agreement between exact and polynomial-filter \
             commute-time distances, got correlation={corr}"
        );
    }

    #[test]
    fn verdict_no_caveat_when_signals_agree() {
        // When the primary signal itself is strong, no caveat is needed
        // even if eigenvalue correlation is also high — they agree.
        let verdict = build_verdict(0.90, 0.88, 0.85, 0.92);
        assert!(verdict.starts_with("STRONG"));
        assert!(!verdict.contains("Note:"));
    }
}
