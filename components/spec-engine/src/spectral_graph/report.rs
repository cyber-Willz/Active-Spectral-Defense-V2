use serde::{Deserialize, Serialize};
use super::{embedding::SpectralEmbedding, error::GraphResult, graph::Graph};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphReport {
    pub num_nodes:              usize,
    pub algebraic_connectivity: f64,
    pub is_connected:           bool,
    pub eigenvalues:            Vec<f64>,
    pub fiedler_vector:         Vec<f64>,
    pub pairwise:               Vec<PairwiseResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairwiseResult {
    pub from:                  usize,
    pub to:                    usize,
    pub label:                 String,
    pub topological_hops:      usize,
    pub commute_time_distance: f64,
    pub fiedler_distance:      f64,
    pub euclidean_distance:    f64,
}

impl GraphReport {
    pub fn build(
        graph:     &Graph,
        embedding: &SpectralEmbedding,
        pairs:     &[(usize, usize, &str)],
    ) -> GraphResult<Self> {
        let pairwise = pairs.iter().map(|&(u, v, label)| {
            Ok(PairwiseResult {
                from: u, to: v, label: label.to_string(),
                topological_hops:      graph.topological_distance(u, v).unwrap_or(usize::MAX),
                commute_time_distance: embedding.geometric_distance(u, v)?,
                fiedler_distance:      embedding.fiedler_distance(u, v)?,
                euclidean_distance:    embedding.euclidean_distance(u, v)?,
            })
        }).collect::<GraphResult<Vec<_>>>()?;

        Ok(GraphReport {
            num_nodes:              graph.num_nodes(),
            algebraic_connectivity: embedding.algebraic_connectivity,
            is_connected:           embedding.algebraic_connectivity > 1e-10,
            eigenvalues:            embedding.eigenvalues.clone(),
            fiedler_vector:         embedding.fiedler_vector().unwrap_or_default(),
            pairwise,
        })
    }

    pub fn print(&self) {
        println!("╔══════════════════════════════════════════════════════╗");
        println!("║          Spectral Graph Analysis Report              ║");
        println!("╠══════════════════════════════════════════════════════╣");
        println!("║  Nodes    : {}", self.num_nodes);
        println!("║  Connected: {}", if self.is_connected { "Yes" } else { "No" });
        println!("║  λ₁ (Fiedler): {:.6}", self.algebraic_connectivity);
        println!("╠──────────────────────────────────────────────────────╣");
        println!("║  Eigenvalues (first 10):");
        for (i, &ev) in self.eigenvalues.iter().take(10).enumerate() {
            let tag = if i == 0 { " (trivial)" } else if i == 1 { " (Fiedler)" } else { "" };
            println!("║    λ{i} = {ev:>10.6}{tag}");
        }
        if self.eigenvalues.len() > 10 {
            println!("║    ... ({} total)", self.eigenvalues.len());
        }
        println!("╠──────────────────────────────────────────────────────╣");
        println!("║  Pairwise distances:");
        println!("║  {:<18} {:>5}  {:>14}  {:>11}  {:>10}", "Label", "Hops", "Commute-Time", "Fiedler", "Euclidean");
        println!("║  {}", "─".repeat(64));
        for r in &self.pairwise {
            let hops = if r.topological_hops == usize::MAX {
                "∞".to_string()
            } else {
                r.topological_hops.to_string()
            };
            println!(
                "║  ({}->{}) {:<10}  {:>5}  {:>14.6}  {:>11.6}  {:>10.6}",
                r.from, r.to, r.label, hops,
                r.commute_time_distance, r.fiedler_distance, r.euclidean_distance
            );
        }
        println!("╚══════════════════════════════════════════════════════╝");
    }
}
