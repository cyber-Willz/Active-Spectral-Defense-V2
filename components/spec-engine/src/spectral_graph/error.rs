use thiserror::Error;

#[derive(Debug, Error)]
pub enum GraphError {
    #[error("Graph must have at least 1 node")]
    EmptyGraph,
    #[error("Node index {0} out of range for graph with {1} nodes")]
    NodeOutOfRange(usize, usize),
    #[error("Eigendecomposition failed to converge after {max_iterations} iterations (residual={residual:.2e})")]
    EigenConvergenceFailed { max_iterations: usize, residual: f64 },
    #[error("Embedding requires at least 2 nodes; graph has {0}")]
    InsufficientNodesForEmbedding(usize),
    #[error("Dimension {0} out of range; matrix has {1} columns")]
    DimensionOutOfRange(usize, usize),
    #[error("No path between node {0} and node {1}")]
    NoPath(usize, usize),
    #[error("JSON error: {0}")]
    Serialisation(#[from] serde_json::Error),
}

pub type GraphResult<T> = Result<T, GraphError>;
