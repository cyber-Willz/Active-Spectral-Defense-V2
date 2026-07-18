//! Matrix-free polynomial approximation of the graph-Laplacian resolvent
//! (`L^+`, the Moore-Penrose pseudoinverse), built on `jacobi_ds`'s
//! Gauss-Jacobi quadrature and Jacobi-polynomial evaluation.
//!
//! ## Why this exists
//!
//! [`super::embedding::SpectralEmbedding::embed`] diagonalises the full
//! `n x n` Laplacian via the classical Jacobi *eigenvalue rotation*
//! algorithm — an `O(n^3)`-per-sweep method that already needs
//! `JacobiConfig::relaxed()`'s 10x iteration budget and a *relative*
//! (rather than absolute) convergence tolerance just to converge on the
//! denser, hub-skewed `L_HNSW` projection graph (see
//! `spectral_homology.rs`). That's workable for the sample-sized graphs
//! this engine currently runs against, but every commute-time-distance
//! query pays for the *entire* spectrum even though
//! [`super::embedding::SpectralEmbedding::geometric_distance`] only ever
//! uses `1/λ_k`.
//!
//! This module fits a degree-`d` polynomial `q(λ) ≈ 1/λ` in a Jacobi basis
//! — via Gauss-Jacobi quadrature projection, exactly analogous to how
//! `jacobi_ds::JacobiConv` re-projects a polynomial from one Jacobi family
//! into another, just against a hand-picked target function (`1/λ`)
//! instead of another `JacobiPoly` — and evaluates `q(L) v` using the same
//! three-term recurrence `JacobiPoly::eval` uses, but with
//! [`super::graph::Graph::laplacian_matvec`] standing in for multiplication
//! by the scalar `x`. This is the standard "polynomial graph filter" trick
//! (ChebNet / GPR-GNN / JacobiConv-style spectral filtering) and costs
//! `O(d * (n + m))` per pair instead of `O(n^3)` for the whole spectrum.
//!
//! ## What this is *not*
//!
//! It is **not** a replacement for [`super::embedding::SpectralEmbedding`].
//! Fiedler cosine similarity and k-subspace alignment in
//! `spectral_homology.rs` genuinely need actual eigenvectors, which this
//! module does not produce — it only ever approximates the *action* of
//! `L^+` on a specific vector. What it gives instead is a fast, scalable,
//! matrix-free commute-time-distance estimate, useful (a) as a cheap
//! cross-check on whether the exact `O(n^3)` eigendecomposition actually
//! converged to something sane (see
//! `spectral_homology::cross_check_ct_with_polynomial_filter`), and (b) as
//! a stand-in for `geometric_distance` on graphs too large for dense
//! diagonalisation.

use super::graph::Graph;
use crate::jacobi_ds::{gauss_jacobi, jacobi_norm_squared, jacobi_value, JacobiError};

/// Degree-`d` Jacobi-polynomial approximation of `f(λ) = 1/λ` over
/// `[lambda_min, lambda_max]`, ready to apply to vectors via
/// [`Self::apply`].
///
/// Uses the Chebyshev weight (`alpha = beta = -0.5`) — the classical
/// minimax-favourable choice for polynomial filters — though the
/// projection integral in [`Self::fit`] is exact via Gauss-Jacobi
/// quadrature for any valid Jacobi parameters.
pub struct ResolventFilter {
    alpha: f64,
    beta: f64,
    /// Ascending-degree coefficients in the `(alpha, beta)` Jacobi basis,
    /// approximating `1/λ` on the mapped domain `[-1, 1]`.
    coeffs: Vec<f64>,
    lambda_min: f64,
    lambda_max: f64,
}

impl ResolventFilter {
    /// Fit a degree-`degree` Jacobi-polynomial approximation to
    /// `f(λ) = 1/λ` on `[lambda_min, lambda_max]`.
    ///
    /// `lambda_min` should be a conservative small positive floor on the
    /// smallest non-trivial eigenvalue you need resolved well — `1/λ` is
    /// unbounded at `λ = 0`, but the trivial (constant) eigenvector never
    /// needs resolving in practice, since [`Self::apply`] is only ever
    /// meant to be called on vectors already orthogonal to the all-ones
    /// vector (e.g. `e_u - e_v`, which sums to zero by construction).
    pub fn fit(lambda_min: f64, lambda_max: f64, degree: usize) -> Result<Self, JacobiError> {
        let (alpha, beta) = (-0.5, -0.5);
        assert!(
            lambda_max > lambda_min,
            "ResolventFilter::fit: empty spectral interval [{lambda_min}, {lambda_max}]"
        );

        // Map λ in [lambda_min, lambda_max] -> x in [-1, 1] (and back).
        let from_x = |x: f64| -> f64 { 0.5 * (x * (lambda_max - lambda_min) + (lambda_max + lambda_min)) };

        // Project f(λ) = 1/λ onto the degree-`degree` Jacobi basis via
        // Gauss-Jacobi quadrature — the same projection JacobiConv::convert
        // performs internally, just against a hand-picked target function
        // instead of another JacobiPoly.
        let quad_n = degree + 4;
        let (nodes, weights) = gauss_jacobi(quad_n, alpha, beta)?;
        let norm_sq: Vec<f64> = (0..=degree).map(|k| jacobi_norm_squared(k, alpha, beta)).collect();

        let f_vals: Vec<f64> = nodes.iter().map(|&x| 1.0 / from_x(x)).collect();
        let mut coeffs = vec![0.0_f64; degree + 1];
        for (k, coeff) in coeffs.iter_mut().enumerate() {
            let mut sum = 0.0;
            for j in 0..nodes.len() {
                let pk = jacobi_value(k, alpha, beta, nodes[j]);
                sum += weights[j] * f_vals[j] * pk;
            }
            *coeff = sum / norm_sq[k];
        }

        Ok(Self { alpha, beta, coeffs, lambda_min, lambda_max })
    }

    /// Apply `q(L) v`, where `q` is this filter's Jacobi-polynomial
    /// approximation of `1/λ`, via the same three-term recurrence
    /// `jacobi_ds::JacobiPoly::eval` uses to evaluate a scalar polynomial —
    /// except every multiplication by the recurrence variable `x` becomes a
    /// call to [`Graph::laplacian_matvec`] on the affinely-mapped Laplacian
    /// instead. This never forms `L` densely and never diagonalises it:
    /// cost is `O(degree * (n + m))`.
    pub fn apply(&self, graph: &Graph, v: &[f64]) -> Vec<f64> {
        let n = v.len();
        let (lmin, lmax) = (self.lambda_min, self.lambda_max);

        // L_mapped * x = (2 L x - (lmax+lmin) x) / (lmax - lmin) — the
        // vector-valued analogue of the scalar affine map used in `fit`.
        let l_mapped = |x: &[f64]| -> Vec<f64> {
            let lx = graph.laplacian_matvec(x);
            (0..n).map(|i| (2.0 * lx[i] - (lmax + lmin) * x[i]) / (lmax - lmin)).collect()
        };

        let mut sum = vec![0.0; n]; // c_0 * P_0(L) v = c_0 * v
        for i in 0..n {
            sum[i] += self.coeffs[0] * v[i];
        }
        if self.coeffs.len() == 1 {
            return sum;
        }

        // P_1(L) v = 0.5 * ((alpha+beta+2) * L_mapped(v) + (alpha-beta) * v)
        let lv = l_mapped(v);
        let mut p_prev2 = v.to_vec(); // P_0(L) v
        let mut p_prev1: Vec<f64> = (0..n)
            .map(|i| 0.5 * ((self.alpha + self.beta + 2.0) * lv[i] + (self.alpha - self.beta) * v[i]))
            .collect();
        for i in 0..n {
            sum[i] += self.coeffs[1] * p_prev1[i];
        }
        if self.coeffs.len() == 2 {
            return sum;
        }

        for (k, coeff) in self.coeffs.iter().enumerate().skip(2) {
            let kf = k as f64;
            let a_plus_b = self.alpha + self.beta;
            let t = 2.0 * kf + a_plus_b;
            let a_coef = 2.0 * kf * (kf + a_plus_b) * (t - 2.0);
            // b_coef(x) = b_scale * x + b_const, split so the `x`-dependent
            // term becomes an L_mapped application and the constant term
            // stays a plain scalar multiply — mirrors jacobi_ds::jacobi_value's
            // `b_coef = (t - 1.0) * (t * (t - 2.0) * x + alpha^2 - beta^2)`.
            let b_scale = (t - 1.0) * (t * (t - 2.0));
            let b_const = (t - 1.0) * (self.alpha * self.alpha - self.beta * self.beta);
            let c_coef = 2.0 * (kf + self.alpha - 1.0) * (kf + self.beta - 1.0) * t;

            let l_p_prev1 = l_mapped(&p_prev1);
            let p_curr: Vec<f64> = (0..n)
                .map(|i| (b_scale * l_p_prev1[i] + b_const * p_prev1[i] - c_coef * p_prev2[i]) / a_coef)
                .collect();

            for i in 0..n {
                sum[i] += coeff * p_curr[i];
            }
            p_prev2 = p_prev1;
            p_prev1 = p_curr;
        }

        sum
    }
}

/// A **guaranteed** upper bound on the Laplacian's largest eigenvalue, via
/// Gershgorin's circle theorem: row `i` of `L = D - A` has diagonal
/// `deg(i)` and `deg(i)` off-diagonal entries of magnitude `1`, so every
/// Gershgorin disc — and therefore every eigenvalue — lies in
/// `[0, 2 * deg(i)]`. Taking the max over `i` gives `[0, 2 * max_degree]`.
///
/// Unlike [`estimate_lambda_max`] (power iteration, which can silently
/// *underestimate* if it hasn't fully converged — particularly on graphs
/// like the phantom-hub-bridged `L_G`, where one high-degree hub node can
/// leave the top eigenspace slow to separate from its neighbours), this is
/// exact and costs a single `O(n)` pass: no iteration, no convergence risk.
///
/// [`ResolventFilter::fit`]'s domain should always be built from this bound
/// (or something at least this large) — an undersized domain sends the
/// mapped Laplacian argument outside `[-1, 1]`, where a degree-40
/// Chebyshev polynomial evaluates to an enormous, eventually
/// `Inf`/`NaN`-valued, result. See
/// `estimate_commute_time_distance`'s non-finite guard for what happens
/// if that domain is undersized anyway.
pub fn gershgorin_lambda_max(graph: &Graph) -> f64 {
    let n = graph.num_nodes();
    let max_degree = (0..n).map(|i| graph.degree(i).unwrap_or(0)).max().unwrap_or(0);
    2.0 * max_degree as f64
}

/// Estimate `lambda_max` via power iteration on the Laplacian — matrix-free,
/// `O(iters * (n + m))`, no eigendecomposition. `L` is symmetric PSD, so
/// power iteration on `L` itself (no shift needed) converges to
/// `lambda_max` whenever the top eigenvalue is non-repeated, which is
/// generic for the k-NN / real-world graphs this engine targets.
pub fn estimate_lambda_max(graph: &Graph, iters: usize) -> f64 {
    let n = graph.num_nodes();
    let mut v: Vec<f64> = (0..n).map(|i| ((i as f64) * 0.618_033_988_75).fract() - 0.5).collect();
    let norm = |x: &[f64]| -> f64 { x.iter().map(|a| a * a).sum::<f64>().sqrt() };
    let nrm0 = norm(&v);
    if nrm0 > 1e-12 {
        for x in v.iter_mut() {
            *x /= nrm0;
        }
    }
    let mut lambda = 0.0;
    for _ in 0..iters.max(1) {
        let lv = graph.laplacian_matvec(&v);
        let nrm = norm(&lv);
        if nrm < 1e-14 {
            break;
        }
        v = lv.iter().map(|x| x / nrm).collect();
        lambda = nrm;
    }
    lambda
}

/// Approximate commute-time (resistance) distance between `u` and `v`,
/// matrix-free, without diagonalising `L`:
/// `d_CT(u,v) ≈ sqrt( (e_u - e_v)^T · q(L) · (e_u - e_v) )`, where `q(L)`
/// applies [`ResolventFilter`] as a stand-in for `L^+`.
///
/// `lambda_min` should be a conservative lower bound on the smallest
/// non-trivial eigenvalue you want the filter to resolve well (see
/// [`ResolventFilter::fit`]); `lambda_max` is typically
/// [`estimate_lambda_max`]'s output times a small safety margin (e.g.
/// `1.05`–`1.1`) since power iteration converges from below.
pub fn estimate_commute_time_distance(
    graph: &Graph,
    u: usize,
    v: usize,
    lambda_min: f64,
    lambda_max: f64,
    degree: usize,
) -> Result<f64, JacobiError> {
    let n = graph.num_nodes();

    // Reject an undersized domain analytically, up front, rather than
    // hoping the polynomial blows up to a non-finite value we can catch
    // after the fact. It doesn't reliably do that: a degree-d Chebyshev
    // polynomial evaluated just outside [-1, 1] grows exponentially in d
    // but is still an ordinary (if astronomically large, e.g. ~1e36)
    // finite f64 well short of f64::MAX/overflow — so `!quad.is_finite()`
    // alone lets a badly wrong-but-finite answer straight through.
    // `gershgorin_lambda_max` is a cheap, *guaranteed* upper bound on the
    // Laplacian's spectral radius (Gershgorin's circle theorem — no
    // iteration, no convergence risk), so comparing against it catches
    // every undersized domain, not just the ones that happen to overflow.
    let true_lambda_max = gershgorin_lambda_max(graph);
    if lambda_max < true_lambda_max {
        return Err(JacobiError::ConvergenceFailure(format!(
            "domain [{lambda_min}, {lambda_max}] doesn't cover the graph's spectrum: \
             gershgorin_lambda_max = {true_lambda_max} > lambda_max = {lambda_max}; \
             use gershgorin_lambda_max(graph) (or something at least that large) for lambda_max"
        )));
    }

    let filter = ResolventFilter::fit(lambda_min, lambda_max, degree)?;
    let mut e = vec![0.0; n];
    if u < n {
        e[u] += 1.0;
    }
    if v < n {
        e[v] -= 1.0;
    }
    let filtered = filter.apply(graph, &e);
    let quad: f64 = e.iter().zip(filtered.iter()).map(|(a, b)| a * b).sum();

    // A non-finite quadratic form means the polynomial blew up for some
    // other reason (e.g. a degenerate lambda_min). `quad.max(0.0)` alone
    // would NOT catch this: Rust's `f64::max` treats a NaN operand as
    // "not the max" and returns the other (finite) operand — so
    // `NaN.max(0.0)` silently evaluates to `0.0`, turning a real
    // numerical failure into a plausible-looking distance of zero instead
    // of surfacing it. This is defense-in-depth alongside the domain
    // check above, which already covers the undersized-lambda_max case.
    if !quad.is_finite() {
        return Err(JacobiError::ConvergenceFailure(format!(
            "polynomial filter produced a non-finite quadratic form ({quad}) for pair \
             ({u}, {v}) with domain [{lambda_min}, {lambda_max}] — the fitted domain likely \
             doesn't cover the graph's true spectrum; try gershgorin_lambda_max for lambda_max"
        )));
    }
    // Small negative values here are ordinary floating-point noise around
    // zero from an imperfect (but finite) polynomial approximation — safe
    // to clamp, now that the non-finite case above is handled separately.
    Ok(quad.max(0.0).sqrt())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spectral_graph::embedding::{JacobiConfig, SpectralEmbedding};

    fn path_graph(n: usize) -> Graph {
        let edges: Vec<(usize, usize)> = (0..n - 1).map(|i| (i, i + 1)).collect();
        Graph::from_edges(n, &edges).unwrap()
    }

    #[test]
    fn lambda_max_matches_exact_top_eigenvalue() {
        let g = path_graph(10);
        let approx = estimate_lambda_max(&g, 500);

        let cfg = JacobiConfig::default();
        let emb = SpectralEmbedding::embed(&g, &cfg).unwrap();
        let exact_max = emb.eigenvalues.iter().cloned().fold(0.0_f64, f64::max);

        assert!(
            (approx - exact_max).abs() / exact_max.max(1.0) < 0.05,
            "approx={approx} exact={exact_max}"
        );
    }

    #[test]
    fn resolvent_commute_time_matches_exact_geometric_distance() {
        let n = 8;
        let g = path_graph(n);
        let cfg = JacobiConfig::default();
        let emb = SpectralEmbedding::embed(&g, &cfg).unwrap();

        let lambda_max = gershgorin_lambda_max(&g);
        // A conservative small floor; the filter only needs to be accurate
        // on the part of the spectrum that (e_u - e_v) actually excites.
        let lambda_min = 1e-3;

        for &(u, v) in &[(0usize, 1usize), (0, 7), (3, 5)] {
            let exact = emb.geometric_distance(u, v).unwrap();
            let approx = estimate_commute_time_distance(&g, u, v, lambda_min, lambda_max, 40).unwrap();
            assert!(
                (approx - exact).abs() / exact.max(1e-6) < 0.15,
                "u={u} v={v} exact={exact:.6} approx={approx:.6}"
            );
        }
    }

    #[test]
    fn gershgorin_bound_is_a_valid_upper_bound_on_lambda_max() {
        let g = path_graph(15);
        let bound = gershgorin_lambda_max(&g);

        let cfg = JacobiConfig::default();
        let emb = SpectralEmbedding::embed(&g, &cfg).unwrap();
        let exact_max = emb.eigenvalues.iter().cloned().fold(0.0_f64, f64::max);

        assert!(
            bound >= exact_max,
            "Gershgorin bound {bound} should upper-bound the exact max eigenvalue {exact_max}"
        );
    }

    #[test]
    fn commute_time_distance_errors_on_undersized_domain_instead_of_returning_zero() {
        // Regression test for the bug this module shipped with: if
        // lambda_max is undersized (smaller than the graph's true spectral
        // radius), the mapped Laplacian argument falls outside [-1, 1] and
        // the degree-d Chebyshev polynomial blows up to a non-finite
        // value. The old code silently clamped that via `quad.max(0.0)`,
        // which — because `f64::max` does not propagate NaN — turned a
        // real failure into an indistinguishable, plausible-looking 0.0
        // for every pair. That must now surface as an `Err`, not a value.
        let g = path_graph(20);
        let true_max = gershgorin_lambda_max(&g);
        let way_too_small = true_max * 0.05; // deliberately undersized domain

        let result = estimate_commute_time_distance(&g, 0, 19, 1e-3, way_too_small, 40);
        assert!(
            result.is_err(),
            "expected an Err for an undersized spectral domain, got {result:?}"
        );
    }

    #[test]
    fn apply_is_linear_in_the_input_vector() {
        // q(L)(a*u + b*v) should equal a*q(L)u + b*q(L)v for any polynomial
        // filter — a basic sanity check on the recurrence implementation.
        let g = path_graph(6);
        let filter = ResolventFilter::fit(1e-3, 8.0, 12).unwrap();

        let u = vec![1.0, 0.5, -0.2, 0.0, 0.3, -0.7];
        let v = vec![0.1, -1.0, 0.4, 0.2, -0.3, 0.6];
        let (a, b) = (2.0, -1.5);

        let combined: Vec<f64> = u.iter().zip(v.iter()).map(|(&x, &y)| a * x + b * y).collect();
        let lhs = filter.apply(&g, &combined);

        let qu = filter.apply(&g, &u);
        let qv = filter.apply(&g, &v);
        let rhs: Vec<f64> = qu.iter().zip(qv.iter()).map(|(&x, &y)| a * x + b * y).collect();

        for i in 0..lhs.len() {
            assert!((lhs[i] - rhs[i]).abs() < 1e-8, "index {i}: lhs={} rhs={}", lhs[i], rhs[i]);
        }
    }
}
