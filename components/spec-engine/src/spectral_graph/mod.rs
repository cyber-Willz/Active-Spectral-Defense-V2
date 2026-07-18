pub mod embedding;
pub mod error;
pub mod graph;
pub mod poly_filter;
pub mod report;

pub use embedding::{build_connected_graph, JacobiConfig, SpectralEmbedding};
pub use error::{GraphError, GraphResult};
pub use graph::Graph;
pub use poly_filter::{
    estimate_commute_time_distance, estimate_lambda_max, gershgorin_lambda_max, ResolventFilter,
};
pub use report::{GraphReport, PairwiseResult};
