use log::{debug, warn};
use serde::{Deserialize, Serialize};

use super::{
    error::{GraphError, GraphResult},
    graph::Graph,
};

/// Tuning knobs for the Jacobi eigendecomposition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JacobiConfig {
    pub max_iterations: usize,
    /// Convergence threshold, expressed **relative to the matrix's own
    /// magnitude** (i.e. the largest diagonal entry), not as an absolute
    /// value. A fixed absolute epsilon becomes unreachable once diagonal
    /// entries (node degree / edge weight) grow past O(1), which is routine
    /// for hub-heavy graphs such as an HNSW k-NN projection graph.
    pub epsilon: f64,
    /// Number of eigenvectors to retain (`None` = all).
    pub dimensions: Option<usize>,
}

impl Default for JacobiConfig {
    /// Suitable for typical sparse network graphs (`L_G`).
    fn default() -> Self {
        JacobiConfig { max_iterations: 2_000, epsilon: 1e-9, dimensions: None }
    }
}

impl JacobiConfig {
    /// Tuned for larger / denser graphs — e.g. the HNSW k-NN projection
    /// graph (`L_HNSW`) — where a few high-degree hub nodes inflate the
    /// Laplacian's magnitude and the number of rotations needed to converge.
    pub fn relaxed() -> Self {
        JacobiConfig { max_iterations: 20_000, epsilon: 1e-6, dimensions: None }
    }
}

/// Continuous spectral-space representation of a discrete graph.
///
/// Each node maps to row `i` in `eigenvector_matrix`; columns are sorted
/// by ascending eigenvalue (λ₀ ≈ 0 trivial, λ₁ = Fiedler value).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpectralEmbedding {
    pub num_nodes: usize,
    pub num_dims: usize,
    pub eigenvector_matrix: Vec<Vec<f64>>,
    pub eigenvalues: Vec<f64>,
    /// Algebraic connectivity (λ₁). Zero iff the graph is disconnected.
    pub algebraic_connectivity: f64,
}

impl SpectralEmbedding {
    pub fn embed(graph: &Graph, cfg: &JacobiConfig) -> GraphResult<Self> {
        let n = graph.num_nodes();
        if n < 2 {
            return Err(GraphError::InsufficientNodesForEmbedding(n));
        }

        let mut l = graph.laplacian();
        let mut u: Vec<Vec<f64>> = (0..n)
            .map(|i| {
                let mut row = vec![0.0; n];
                row[i] = 1.0;
                row
            })
            .collect();

        // Scale the convergence threshold to the matrix's own magnitude.
        // Without this, hub-heavy graphs (large diagonal / degree entries)
        // can never drive the *absolute* max off-diagonal below a tiny
        // fixed epsilon within any reasonable iteration budget.
        let scale = (0..n).map(|i| l[i][i].abs()).fold(1.0_f64, f64::max);
        let abs_epsilon = cfg.epsilon * scale;

        let mut converged = false;
        for iter in 0..cfg.max_iterations {
            let (max_val, p, q) = off_diagonal_max(&l, n);
            if max_val < abs_epsilon {
                debug!(
                    "Jacobi converged after {iter} iterations \
                     (residual={max_val:.2e}, scale={scale:.2e})"
                );
                converged = true;
                break;
            }
            let (c, s) = jacobi_cs(l[p][p], l[q][q], l[p][q]);
            apply_jacobi_rotation_to_l(&mut l, n, p, q, c, s);
            for i in 0..n {
                let u_ip = u[i][p];
                let u_iq = u[i][q];
                u[i][p] = c * u_ip - s * u_iq;
                u[i][q] = s * u_ip + c * u_iq;
            }
        }

        if !converged {
            let residual = off_diagonal_max(&l, n).0;
            let relative_residual = residual / scale;
            warn!(
                "Jacobi did not fully converge after {} iterations \
                 (residual={residual:.2e}, relative={relative_residual:.2e})",
                cfg.max_iterations
            );
            // Jacobi converges quadratically near the fixed point, so a
            // small *relative* residual still yields a very good eigenbasis.
            // This embedding feeds approximate distance / homology
            // comparisons rather than requiring an exact eigendecomposition,
            // so a relative tolerance — not an absolute one — is the
            // correct hard-failure bar.
            if relative_residual > 1e-3 {
                return Err(GraphError::EigenConvergenceFailed {
                    max_iterations: cfg.max_iterations,
                    residual,
                });
            }
        }

        // The graph Laplacian is positive semi-definite; any negative diagonal
        // value after Jacobi is floating-point noise.  Clamp to zero before
        // sorting so λ₀ ≈ 0 (trivial) and λ₁ ≥ 0 (Fiedler) are correctly placed.
        let mut pairs: Vec<(f64, usize)> = (0..n)
            .map(|i| (l[i][i].max(0.0), i))
            .collect();
        pairs.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

        let num_dims = cfg.dimensions.unwrap_or(n).min(n);
        let eigenvalues: Vec<f64> = pairs[..num_dims].iter().map(|&(ev, _)| ev).collect();
        let eigenvector_matrix: Vec<Vec<f64>> = (0..n)
            .map(|i| pairs[..num_dims].iter().map(|&(_, c)| u[i][c]).collect())
            .collect();

        let algebraic_connectivity = if num_dims > 1 { eigenvalues[1] } else { 0.0 };

        Ok(SpectralEmbedding { num_nodes: n, num_dims, eigenvector_matrix, eigenvalues, algebraic_connectivity })
    }

    // ── Distance metrics ──────────────────────────────────────────────────────

    /// **Commute-time (resistance) distance** — weights each dim `k` by `1/λₖ`.
    /// Correctly preserves topological ordering on asymmetric graphs.
    /// `d_CT(u,v) = sqrt( Σₖ (φₖ(u) − φₖ(v))² / λₖ )`  (k ≥ 1, λₖ > 0)
    pub fn geometric_distance(&self, u: usize, v: usize) -> GraphResult<f64> {
        if self.num_dims < 2 {
            return Err(GraphError::InsufficientNodesForEmbedding(self.num_dims));
        }
        self.validate_node(u)?;
        self.validate_node(v)?;
        let dist: f64 = (1..self.num_dims)
            .filter_map(|k| {
                let lambda = self.eigenvalues[k];
                if lambda < 1e-10 {
                    return None;
                }
                let d = self.eigenvector_matrix[u][k] - self.eigenvector_matrix[v][k];
                Some((d * d) / lambda)
            })
            .sum::<f64>()
            .sqrt();
        Ok(dist)
    }

    /// Raw Euclidean distance in eigenvector space (collapses on symmetric graphs;
    /// use for diagnostics only).
    pub fn euclidean_distance(&self, u: usize, v: usize) -> GraphResult<f64> {
        self.validate_node(u)?;
        self.validate_node(v)?;
        let dist: f64 = (0..self.num_dims)
            .map(|k| {
                let d = self.eigenvector_matrix[u][k] - self.eigenvector_matrix[v][k];
                d * d
            })
            .sum::<f64>()
            .sqrt();
        Ok(dist)
    }

    /// Fiedler-only 1-D distance (fast structural-split approximation).
    ///
    /// On disconnected graphs λ₁ = 0 and the standard Fiedler vector gives
    /// zero separation.  This implementation scans forward to the first
    /// eigenvector dimension with λₖ > 1e-10 (the first non-trivial split)
    /// so it remains informative even on partially-disconnected topologies.
    pub fn fiedler_distance(&self, u: usize, v: usize) -> GraphResult<f64> {
        if self.num_dims < 2 {
            return Err(GraphError::InsufficientNodesForEmbedding(self.num_dims));
        }
        self.validate_node(u)?;
        self.validate_node(v)?;
        let first_nontrivial = self.eigenvalues
            .iter()
            .position(|&ev| ev > 1e-10)
            .unwrap_or(1);
        Ok((self.eigenvector_matrix[u][first_nontrivial]
            - self.eigenvector_matrix[v][first_nontrivial])
            .abs())
    }

    pub fn coordinate(&self, node: usize, dim: usize) -> GraphResult<f64> {
        self.validate_node(node)?;
        if dim >= self.num_dims {
            return Err(GraphError::DimensionOutOfRange(dim, self.num_dims));
        }
        Ok(self.eigenvector_matrix[node][dim])
    }

    pub fn fiedler_vector(&self) -> GraphResult<Vec<f64>> {
        if self.num_dims < 2 {
            return Err(GraphError::InsufficientNodesForEmbedding(self.num_dims));
        }
        Ok((0..self.num_nodes).map(|i| self.eigenvector_matrix[i][1]).collect())
    }

    /// Extract the embedding coordinates for a single node as a flat `Vec<f32>`.
    /// Used when appending spectral features to the anomaly encoder input.
    pub fn node_coords_f32(&self, node: usize) -> GraphResult<Vec<f32>> {
        self.validate_node(node)?;
        Ok(self.eigenvector_matrix[node].iter().map(|&x| x as f32).collect())
    }

    #[inline]
    fn validate_node(&self, idx: usize) -> GraphResult<()> {
        if idx >= self.num_nodes {
            Err(GraphError::NodeOutOfRange(idx, self.num_nodes))
        } else {
            Ok(())
        }
    }
}

// ─── Jacobi helpers ──────────────────────────────────────────────────────────

#[inline]
fn off_diagonal_max(l: &[Vec<f64>], n: usize) -> (f64, usize, usize) {
    let (mut max_val, mut p, mut q) = (0.0_f64, 0, 1);
    for i in 0..n {
        for j in (i + 1)..n {
            let v = l[i][j].abs();
            if v > max_val {
                max_val = v;
                p = i;
                q = j;
            }
        }
    }
    (max_val, p, q)
}

#[inline]
fn jacobi_cs(l_pp: f64, l_qq: f64, l_pq: f64) -> (f64, f64) {
    let theta = (l_qq - l_pp) / (2.0 * l_pq);
    let t = if theta >= 0.0 {
        1.0 / (theta + (theta * theta + 1.0).sqrt())
    } else {
        -1.0 / (-theta + (theta * theta + 1.0).sqrt())
    };
    let c = 1.0 / (1.0 + t * t).sqrt();
    (c, t * c)
}

fn apply_jacobi_rotation_to_l(
    l: &mut Vec<Vec<f64>>,
    n: usize,
    p: usize,
    q: usize,
    c: f64,
    s: f64,
) {
    let (l_pp, l_qq, l_pq) = (l[p][p], l[q][q], l[p][q]);
    l[p][p] = c * c * l_pp - 2.0 * s * c * l_pq + s * s * l_qq;
    l[q][q] = s * s * l_pp + 2.0 * s * c * l_pq + c * c * l_qq;
    l[p][q] = 0.0;
    l[q][p] = 0.0;
    for i in 0..n {
        if i != p && i != q {
            let (l_ip, l_iq) = (l[i][p], l[i][q]);
            l[i][p] = c * l_ip - s * l_iq;
            l[p][i] = l[i][p];
            l[i][q] = s * l_ip + c * l_iq;
            l[q][i] = l[i][q];
        }
    }
}

// ─── Phantom graph builder ────────────────────────────────────────────────────

/// Build a connected supergraph from `raw_edges` over `n` nodes.
///
/// When the physical edge set produces a disconnected graph (λ₁ = 0), a
/// single **phantom hub** node at index `n` is appended and stapled to:
///   • every node whose connected component is not reachable from node 0, and
///   • node 0 itself (so the hub bridges ALL components into one).
///
/// The hub node is internal — it is never inserted into `entity_index` and
/// is therefore invisible to all public distance / blast-radius APIs.
///
/// Returns `(graph, hub_was_injected)`.
pub fn build_connected_graph(
    n: usize,
    raw_edges: &[(usize, usize)],
) -> GraphResult<(Graph, bool)> {
    let phys = Graph::from_edges(n, raw_edges)?;

    // Fast path: already connected.
    if phys.is_connected() {
        return Ok((phys, false));
    }

    // Identify which nodes are unreachable from node 0.
    let bfs0 = phys.bfs_distances(0)?;
    let hub = n; // virtual hub lives at index n
    let n_aug = n + 1;

    let mut aug_edges: Vec<(usize, usize)> = raw_edges.to_vec();
    // Connect node 0 → hub so the hub itself is reachable from 0.
    aug_edges.push((0, hub));
    // Connect every isolated node → hub.
    for (node_idx, dist) in bfs0.iter().enumerate() {
        if dist.is_none() {
            aug_edges.push((node_idx, hub));
        }
    }

    let aug = Graph::from_edges(n_aug, &aug_edges)?;
    debug!(
        "Phantom hub injected at index {hub}: {} augmented edges total",
        aug_edges.len()
    );
    Ok((aug, true))
}
