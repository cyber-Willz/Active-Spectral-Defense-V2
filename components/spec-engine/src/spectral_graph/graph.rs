use std::collections::VecDeque;

use log::debug;
use serde::{Deserialize, Serialize};

use super::error::{GraphError, GraphResult};

/// Strongly-typed, copy-cheap node identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub usize);

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Node({})", self.0)
    }
}

/// Undirected, unweighted graph stored as a dense adjacency list.
/// All mutations validate arguments and return `GraphError` rather than panicking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Graph {
    num_nodes: usize,
    adjacency: Vec<Vec<usize>>,
}

impl Graph {
    pub fn new(num_nodes: usize) -> GraphResult<Self> {
        if num_nodes == 0 {
            return Err(GraphError::EmptyGraph);
        }
        Ok(Graph { num_nodes, adjacency: vec![Vec::new(); num_nodes] })
    }

    pub fn add_edge(&mut self, u: usize, v: usize) -> GraphResult<()> {
        self.validate_node(u)?;
        self.validate_node(v)?;
        if u == v {
            debug!("Skipping self-loop on node {u}");
            return Ok(());
        }
        if !self.adjacency[u].contains(&v) {
            self.adjacency[u].push(v);
            self.adjacency[v].push(u);
        }
        Ok(())
    }

    pub fn from_edges(num_nodes: usize, edges: &[(usize, usize)]) -> GraphResult<Self> {
        let mut g = Graph::new(num_nodes)?;
        for &(u, v) in edges {
            g.add_edge(u, v)?;
        }
        Ok(g)
    }

    #[inline]
    pub fn num_nodes(&self) -> usize {
        self.num_nodes
    }

    pub fn degree(&self, idx: usize) -> GraphResult<usize> {
        self.validate_node(idx)?;
        Ok(self.adjacency[idx].len())
    }

    pub fn neighbours(&self, idx: usize) -> GraphResult<&[usize]> {
        self.validate_node(idx)?;
        Ok(&self.adjacency[idx])
    }

    /// BFS shortest-path hop distance.
    pub fn topological_distance(&self, start: usize, end: usize) -> GraphResult<usize> {
        self.validate_node(start)?;
        self.validate_node(end)?;
        if start == end {
            return Ok(0);
        }

        let mut dist = vec![usize::MAX; self.num_nodes];
        dist[start] = 0;
        let mut queue = VecDeque::with_capacity(self.num_nodes);
        queue.push_back(start);

        while let Some(curr) = queue.pop_front() {
            let d = dist[curr];
            if curr == end {
                return Ok(d);
            }
            for &nbr in &self.adjacency[curr] {
                if dist[nbr] == usize::MAX {
                    dist[nbr] = d + 1;
                    queue.push_back(nbr);
                }
            }
        }
        Err(GraphError::NoPath(start, end))
    }

    /// Full BFS distance vector from `start`. Unreachable nodes → `None`.
    pub fn bfs_distances(&self, start: usize) -> GraphResult<Vec<Option<usize>>> {
        self.validate_node(start)?;
        let mut dist = vec![None; self.num_nodes];
        dist[start] = Some(0);
        let mut queue = VecDeque::with_capacity(self.num_nodes);
        queue.push_back(start);
        while let Some(curr) = queue.pop_front() {
            let d = dist[curr].unwrap();
            for &nbr in &self.adjacency[curr] {
                if dist[nbr].is_none() {
                    dist[nbr] = Some(d + 1);
                    queue.push_back(nbr);
                }
            }
        }
        Ok(dist)
    }

    /// Returns true if all nodes are reachable from node 0.
    pub fn is_connected(&self) -> bool {
        if self.num_nodes <= 1 {
            return true;
        }
        match self.bfs_distances(0) {
            Ok(dists) => dists.iter().all(|d| d.is_some()),
            Err(_) => false,
        }
    }

    /// Unnormalised Laplacian **L = D − A** as a dense row-major matrix.
    pub fn laplacian(&self) -> Vec<Vec<f64>> {
        let n = self.num_nodes;
        let mut l = vec![vec![0.0_f64; n]; n];
        for i in 0..n {
            l[i][i] = self.adjacency[i].len() as f64;
            for &j in &self.adjacency[i] {
                l[i][j] = -1.0;
            }
        }
        l
    }

    /// `L * v`, where `L = D - A` is the unnormalised graph Laplacian,
    /// computed directly from the adjacency list without ever forming `L`
    /// densely. `O(n + m)` per call, versus the `O(n^2)` a dense multiply
    /// against [`Self::laplacian`] would cost. This is what makes
    /// matrix-free polynomial spectral filtering (see
    /// `spectral_graph::poly_filter`) cheaper than exact eigendecomposition
    /// for large graphs — the whole point of avoiding the dense matrix in
    /// the first place.
    pub fn laplacian_matvec(&self, v: &[f64]) -> Vec<f64> {
        debug_assert_eq!(
            v.len(),
            self.num_nodes,
            "laplacian_matvec: vector length {} != {} nodes",
            v.len(),
            self.num_nodes
        );
        (0..self.num_nodes)
            .map(|i| {
                let deg = self.adjacency[i].len() as f64;
                let mut acc = deg * v[i];
                for &j in &self.adjacency[i] {
                    acc -= v[j];
                }
                acc
            })
            .collect()
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

impl std::fmt::Display for Graph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Graph ({} nodes):", self.num_nodes)?;
        for (i, nbrs) in self.adjacency.iter().enumerate() {
            write!(f, "  Node {i}: [")?;
            for (k, &nbr) in nbrs.iter().enumerate() {
                if k > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{nbr}")?;
            }
            writeln!(f, "]")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn laplacian_matvec_matches_dense_multiply() {
        let edges = [(0, 1), (1, 2), (2, 3), (3, 0), (0, 2)];
        let g = Graph::from_edges(4, &edges).unwrap();
        let l = g.laplacian();

        let v = vec![1.3, -0.7, 2.1, 0.4];
        let expected: Vec<f64> = (0..4)
            .map(|i| (0..4).map(|j| l[i][j] * v[j]).sum())
            .collect();
        let actual = g.laplacian_matvec(&v);

        for i in 0..4 {
            assert!(
                (expected[i] - actual[i]).abs() < 1e-10,
                "row {i}: dense={} matvec={}",
                expected[i],
                actual[i]
            );
        }
    }
}
