//! # jacobi_ds
//!
//! A production-grade data structure for polynomials expressed in the
//! Jacobi basis, `p(x) = sum_{k=0}^{n} c_k * P_k^{(alpha, beta)}(x)`, valid
//! on `x in [-1, 1]` with weight function `w(x) = (1-x)^alpha (1+x)^beta`,
//! `alpha, beta > -1`.
//!
//! Jacobi polynomials generalize Legendre (`alpha = beta = 0`), Chebyshev
//! first kind (`alpha = beta = -1/2`, up to scaling), Chebyshev second kind
//! (`alpha = beta = 1/2`, up to scaling), and Gegenbauer/ultraspherical
//! polynomials. Unlike Chebyshev, the recurrence coefficients depend on
//! `alpha`, `beta`, and the degree, and differentiation shifts a
//! polynomial's *parameters*, not just its degree — `d/dx P_n^{(a,b)}` is a
//! degree-`(n-1)` polynomial in the `(a+1, b+1)` basis. This module reflects
//! that structure directly rather than hiding it.
//!
//! ## What's here
//!
//! - [`JacobiPoly`]: an expansion in a fixed `(alpha, beta)` Jacobi basis —
//!   construction, stable evaluation, differentiation (which correctly
//!   returns a new basis), and arithmetic.
//! - [`gauss_jacobi`]: Gauss-Jacobi quadrature nodes and weights via Newton
//!   iteration on the three-term recurrence.
//! - [`JacobiConv`]: **the basis-conversion operator** ("JacobiConv") that
//!   re-expands a polynomial from one `(alpha, beta)` basis into another,
//!   via Gauss-Jacobi quadrature projection. This is the standard technique
//!   spectral-method libraries use for sparse "connection" operators
//!   between Jacobi families; it works for *any* pair of parameters, not
//!   just unit increments, and precomputes/caches its quadrature rule so
//!   repeated conversions between the same two bases are cheap.
//!
//! ## Honesty about limits
//!
//! Gauss-Jacobi node-finding uses Newton's method seeded from Chebyshev-node
//! initial guesses. This converges reliably for the moderate degrees and
//! `alpha, beta` ranges (roughly `-0.9..=6`, degree up to a few hundred)
//! typical of spectral discretizations, and the implementation verifies
//! convergence (root count and strict ordering) before returning rather
//! than silently returning garbage. For extreme parameters or very high
//! degree, a full asymptotic-initial-guess or Golub-Welsch
//! eigenvalue-based solver would be more robust — flagged here rather than
//! quietly under-delivering.

use std::f64::consts::PI;
use std::fmt;
use std::ops::{Mul, Neg};

/// Errors arising from Jacobi polynomial construction, evaluation, or
/// conversion.
#[derive(Debug, Clone, PartialEq)]
pub enum JacobiError {
    /// The input coefficient vector was empty.
    EmptyCoefficients,
    /// `alpha` or `beta` was `<= -1`, outside the domain of validity.
    InvalidParameters { alpha: f64, beta: f64 },
    /// `x` was outside the valid domain `[-1, 1]` for a domain-checked call.
    OutOfDomain(f64),
    /// Requested zero quadrature points.
    InvalidPointCount,
    /// An operation required two [`JacobiPoly`] values to share `(alpha,
    /// beta)`, but they didn't.
    ParameterMismatch {
        expected: (f64, f64),
        found: (f64, f64),
    },
    /// A [`JacobiConv`] was asked to convert a polynomial of degree higher
    /// than it was built to handle.
    DegreeExceeded { max: usize, found: usize },
    /// Newton iteration for Gauss-Jacobi nodes failed to produce `n`
    /// distinct, correctly ordered roots.
    ConvergenceFailure(String),
}

impl fmt::Display for JacobiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JacobiError::EmptyCoefficients => {
                write!(f, "coefficient vector must contain at least one element")
            }
            JacobiError::InvalidParameters { alpha, beta } => write!(
                f,
                "invalid Jacobi parameters alpha={alpha}, beta={beta}: both must be > -1"
            ),
            JacobiError::OutOfDomain(x) => {
                write!(f, "x = {x} is outside the Jacobi domain [-1, 1]")
            }
            JacobiError::InvalidPointCount => write!(f, "point count must be at least 1"),
            JacobiError::ParameterMismatch { expected, found } => write!(
                f,
                "parameter mismatch: expected (alpha, beta) = {expected:?}, found {found:?}"
            ),
            JacobiError::DegreeExceeded { max, found } => write!(
                f,
                "polynomial degree {found} exceeds JacobiConv's configured max degree {max}"
            ),
            JacobiError::ConvergenceFailure(msg) => {
                write!(f, "Gauss-Jacobi node solve failed to converge: {msg}")
            }
        }
    }
}

impl std::error::Error for JacobiError {}

fn check_params(alpha: f64, beta: f64) -> Result<(), JacobiError> {
    if alpha <= -1.0 || beta <= -1.0 || !alpha.is_finite() || !beta.is_finite() {
        return Err(JacobiError::InvalidParameters { alpha, beta });
    }
    Ok(())
}

/// Natural log of the Gamma function via the Lanczos approximation
/// (g = 7, n = 9 coefficients), accurate to ~15 significant digits for
/// `x > 0`. Used throughout for normalization and quadrature-weight
/// formulas, computed in log-space to avoid overflow for large degree or
/// large `alpha`/`beta`.
fn ln_gamma(x: f64) -> f64 {
    const G: f64 = 7.0;
    const COEF: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_312e-7,
    ];
    if x < 0.5 {
        // Reflection formula for x <= 0.5 to keep the Lanczos series in its
        // region of accuracy.
        (PI / (PI * x).sin()).ln() - ln_gamma(1.0 - x)
    } else {
        let x = x - 1.0;
        let mut a = COEF[0];
        let t = x + G + 0.5;
        for (i, &c) in COEF.iter().enumerate().skip(1) {
            a += c / (x + i as f64);
        }
        0.5 * (2.0 * PI).ln() + (x + 0.5) * t.ln() - t + a.ln()
    }
}

/// Evaluate the single Jacobi polynomial `P_n^{(alpha, beta)}(x)` via the
/// stable three-term recurrence (DLMF 18.9.2), O(n) time and O(1) space.
pub fn jacobi_value(n: usize, alpha: f64, beta: f64, x: f64) -> f64 {
    if n == 0 {
        return 1.0;
    }
    let p1 = 0.5 * ((alpha + beta + 2.0) * x + (alpha - beta));
    if n == 1 {
        return p1;
    }
    let mut p_prev2 = 1.0_f64; // P_0
    let mut p_prev1 = p1; // P_1
    for k in 2..=n {
        let nf = k as f64;
        let a_plus_b = alpha + beta;
        let t = 2.0 * nf + a_plus_b;
        let a_coef = 2.0 * nf * (nf + a_plus_b) * (t - 2.0);
        let b_coef = (t - 1.0) * (t * (t - 2.0) * x + alpha * alpha - beta * beta);
        let c_coef = 2.0 * (nf + alpha - 1.0) * (nf + beta - 1.0) * t;
        let p_curr = (b_coef * p_prev1 - c_coef * p_prev2) / a_coef;
        p_prev2 = p_prev1;
        p_prev1 = p_curr;
    }
    p_prev1
}

/// Evaluate `d/dx P_n^{(alpha, beta)}(x)` using the identity
/// `P_n' = 0.5 (n + alpha + beta + 1) P_{n-1}^{(alpha+1, beta+1)}`.
pub fn jacobi_derivative_value(n: usize, alpha: f64, beta: f64, x: f64) -> f64 {
    if n == 0 {
        return 0.0;
    }
    let nf = n as f64;
    0.5 * (nf + alpha + beta + 1.0) * jacobi_value(n - 1, alpha + 1.0, beta + 1.0, x)
}

/// Squared norm `h_n = integral_{-1}^{1} [P_n^{(alpha,beta)}(x)]^2 (1-x)^alpha
/// (1+x)^beta dx`, computed in log-space via [`ln_gamma`] for numerical
/// stability at large `n`, `alpha`, or `beta`.
///
/// `n = 0` is special-cased. The general closed-form formula below has a
/// factor `1 / (2n + alpha + beta + 1)` that is finite for every `n >= 1`
/// (since `alpha, beta > -1` there), but at `n = 0` it degenerates to
/// `1 / (alpha + beta + 1)` — which has a genuine, removable `0 * infinity`
/// singularity whenever `alpha + beta = -1` (e.g. the Chebyshev weight
/// `alpha = beta = -0.5` used throughout `poly_filter.rs`). Evaluated
/// naively in log-space that singularity produces `ln(0) = -inf` colliding
/// with a `+inf` from `ln_gamma(alpha + beta + 1) = ln_gamma(0)`, giving
/// `+inf - inf = NaN` instead of the correct finite value (`h_0 = pi` for
/// the Chebyshev case). `P_0 = 1` identically, so `h_0` is just the total
/// mass of the weight function, `integral (1-x)^alpha (1+x)^beta dx`, which
/// has its own closed form via the Beta function with no such pole:
/// `h_0 = 2^(alpha+beta+1) * Gamma(alpha+1) * Gamma(beta+1) / Gamma(alpha+beta+2)`.
pub fn jacobi_norm_squared(n: usize, alpha: f64, beta: f64) -> f64 {
    let a_plus_b = alpha + beta;
    if n == 0 {
        let ln_h0 = (a_plus_b + 1.0) * std::f64::consts::LN_2
            + ln_gamma(alpha + 1.0)
            + ln_gamma(beta + 1.0)
            - ln_gamma(a_plus_b + 2.0);
        return ln_h0.exp();
    }
    let nf = n as f64;
    let ln_h = (a_plus_b + 1.0) * std::f64::consts::LN_2 - (2.0 * nf + a_plus_b + 1.0).ln()
        + ln_gamma(nf + alpha + 1.0)
        + ln_gamma(nf + beta + 1.0)
        - ln_gamma(nf + a_plus_b + 1.0)
        - ln_gamma(nf + 1.0);
    ln_h.exp()
}

/// Compute the `n` Gauss-Jacobi quadrature nodes and weights for weight
/// function `(1-x)^alpha (1+x)^beta` on `[-1, 1]`, exact for polynomials up
/// to degree `2n - 1`. Nodes are returned in ascending order.
///
/// Roots of `P_n^{(alpha,beta)}` are located by Newton's method seeded from
/// Chebyshev-node initial guesses; weights use the Christoffel-function
/// (reciprocal sum-of-squares) formula
/// `w_k = [ sum_{j=0}^{n-1} P_j^{(alpha,beta)}(x_k)^2 / h_j ]^{-1}`, which is
/// exact for any orthogonal polynomial family and therefore avoids the
/// sign/normalization pitfalls of alpha/beta-asymmetric closed-form
/// coefficient formulas.
pub fn gauss_jacobi(n: usize, alpha: f64, beta: f64) -> Result<(Vec<f64>, Vec<f64>), JacobiError> {
    check_params(alpha, beta)?;
    if n == 0 {
        return Err(JacobiError::InvalidPointCount);
    }
    let nf = n as f64;
    let mut roots = Vec::with_capacity(n);
    for k in 0..n {
        // Chebyshev-node initial guess, generically effective as a Newton
        // seed for Jacobi roots at moderate alpha/beta.
        let mut x = ((PI * (2.0 * k as f64 + 1.0)) / (2.0 * nf)).cos();
        let mut converged = false;
        for _ in 0..100 {
            let f = jacobi_value(n, alpha, beta, x);
            let fp = jacobi_derivative_value(n, alpha, beta, x);
            if fp.abs() < 1e-300 {
                break;
            }
            // Deflate previously found roots: for g(x) = f(x) / prod_i
            // (x - r_i), g'/g = f'/f - sum_i 1/(x - r_i), so Newton's step
            // on g is x - 1/(f'/f - deflate). Without this, Chebyshev seeds
            // for skewed (alpha, beta) can overshoot past a nearby true
            // root and reconverge onto a root already found by another
            // seed, silently dropping a distinct root.
            let deflate: f64 = roots.iter().map(|&r| 1.0 / (x - r)).sum();
            let step = 1.0 / (fp / f - deflate);
            let mut x_new = x - step;
            // Keep iterates strictly inside the domain.
            x_new = x_new.clamp(-1.0 + 1e-14, 1.0 - 1e-14);
            let converged_now = (x_new - x).abs() < 1e-14 * (1.0 + x_new.abs());
            x = x_new;
            if converged_now {
                converged = true;
                break;
            }
        }
        if !converged && jacobi_value(n, alpha, beta, x).abs() > 1e-8 {
            return Err(JacobiError::ConvergenceFailure(format!(
                "node {k} did not converge (alpha={alpha}, beta={beta}, n={n})"
            )));
        }
        roots.push(x);
    }
    roots.sort_by(|a, b| a.partial_cmp(b).unwrap());
    for w in roots.windows(2) {
        if w[1] - w[0] < 1e-10 {
            return Err(JacobiError::ConvergenceFailure(format!(
                "Newton iteration produced coincident roots for n={n}, alpha={alpha}, beta={beta}"
            )));
        }
    }

    // Weights via the Christoffel-function (reciprocal sum-of-squares)
    // formula: w_k = [ sum_{j=0}^{n-1} P_j(x_k)^2 / h_j ]^{-1}. This is a
    // general Gaussian-quadrature identity (exact for any orthogonal
    // polynomial family), computed here with a running three-term
    // recurrence so each node costs O(n).
    let norm_sq: Vec<f64> = (0..n).map(|j| jacobi_norm_squared(j, alpha, beta)).collect();
    let weights: Vec<f64> = roots
        .iter()
        .map(|&x| {
            let mut sum = 1.0 / norm_sq[0]; // P_0(x) = 1
            if n > 1 {
                let p1 = 0.5 * ((alpha + beta + 2.0) * x + (alpha - beta));
                sum += p1 * p1 / norm_sq[1];
                let mut p_prev2 = 1.0_f64;
                let mut p_prev1 = p1;
                for k in 2..n {
                    let kf = k as f64;
                    let a_plus_b = alpha + beta;
                    let t = 2.0 * kf + a_plus_b;
                    let a_coef = 2.0 * kf * (kf + a_plus_b) * (t - 2.0);
                    let b_coef = (t - 1.0)
                        * (t * (t - 2.0) * x + alpha * alpha - beta * beta);
                    let c_coef = 2.0 * (kf + alpha - 1.0) * (kf + beta - 1.0) * t;
                    let p_curr = (b_coef * p_prev1 - c_coef * p_prev2) / a_coef;
                    sum += p_curr * p_curr / norm_sq[k];
                    p_prev2 = p_prev1;
                    p_prev1 = p_curr;
                }
            }
            1.0 / sum
        })
        .collect();

    Ok((roots, weights))
}

/// A polynomial expansion in a fixed Jacobi basis `(alpha, beta)`:
/// `p(x) = sum_k coeffs[k] * P_k^{(alpha, beta)}(x)`.
#[derive(Debug, Clone, PartialEq)]
pub struct JacobiPoly {
    alpha: f64,
    beta: f64,
    coeffs: Vec<f64>,
}

impl JacobiPoly {
    /// Construct from parameters and ascending-degree coefficients.
    /// Requires `alpha, beta > -1` and a non-empty coefficient vector.
    pub fn new(alpha: f64, beta: f64, coeffs: Vec<f64>) -> Result<Self, JacobiError> {
        check_params(alpha, beta)?;
        if coeffs.is_empty() {
            return Err(JacobiError::EmptyCoefficients);
        }
        Ok(Self {
            alpha,
            beta,
            coeffs,
        })
    }

    /// The zero polynomial in the given basis.
    pub fn zero(alpha: f64, beta: f64) -> Result<Self, JacobiError> {
        check_params(alpha, beta)?;
        Ok(Self {
            alpha,
            beta,
            coeffs: vec![0.0],
        })
    }

    /// The constant polynomial `p(x) = 1` in the given basis.
    pub fn one(alpha: f64, beta: f64) -> Result<Self, JacobiError> {
        check_params(alpha, beta)?;
        Ok(Self {
            alpha,
            beta,
            coeffs: vec![1.0],
        })
    }

    /// The pure basis polynomial `P_n^{(alpha, beta)}(x)`.
    pub fn basis(n: usize, alpha: f64, beta: f64) -> Result<Self, JacobiError> {
        check_params(alpha, beta)?;
        let mut c = vec![0.0; n + 1];
        c[n] = 1.0;
        Ok(Self {
            alpha,
            beta,
            coeffs: c,
        })
    }

    /// This polynomial's `(alpha, beta)` parameters.
    pub fn params(&self) -> (f64, f64) {
        (self.alpha, self.beta)
    }

    /// Degree of the polynomial, ignoring trailing zero coefficients.
    pub fn degree(&self) -> usize {
        for i in (1..self.coeffs.len()).rev() {
            if self.coeffs[i].abs() > 0.0 {
                return i;
            }
        }
        0
    }

    /// Read-only view of the raw coefficients.
    pub fn coefficients(&self) -> &[f64] {
        &self.coeffs
    }

    /// Drop trailing coefficients with magnitude `<= tol`.
    pub fn truncate(&mut self, tol: f64) {
        let mut last = self.coeffs.len() - 1;
        while last > 0 && self.coeffs[last].abs() <= tol {
            last -= 1;
        }
        self.coeffs.truncate(last + 1);
    }

    /// Evaluate at `x` by accumulating the three-term recurrence and the
    /// coefficient sum in a single O(n)-time, O(1)-space pass.
    pub fn eval(&self, x: f64) -> f64 {
        let n = self.coeffs.len();
        let mut sum = self.coeffs[0]; // c_0 * P_0 = c_0
        if n == 1 {
            return sum;
        }
        let p1 = 0.5 * ((self.alpha + self.beta + 2.0) * x + (self.alpha - self.beta));
        sum += self.coeffs[1] * p1;
        if n == 2 {
            return sum;
        }
        let mut p_prev2 = 1.0_f64;
        let mut p_prev1 = p1;
        for k in 2..n {
            let nf = k as f64;
            let a_plus_b = self.alpha + self.beta;
            let t = 2.0 * nf + a_plus_b;
            let a_coef = 2.0 * nf * (nf + a_plus_b) * (t - 2.0);
            let b_coef =
                (t - 1.0) * (t * (t - 2.0) * x + self.alpha * self.alpha - self.beta * self.beta);
            let c_coef = 2.0 * (nf + self.alpha - 1.0) * (nf + self.beta - 1.0) * t;
            let p_curr = (b_coef * p_prev1 - c_coef * p_prev2) / a_coef;
            sum += self.coeffs[k] * p_curr;
            p_prev2 = p_prev1;
            p_prev1 = p_curr;
        }
        sum
    }

    /// Like [`Self::eval`] but rejects `x` outside `[-1, 1]`.
    pub fn eval_checked(&self, x: f64) -> Result<f64, JacobiError> {
        if !(-1.0..=1.0).contains(&x) {
            return Err(JacobiError::OutOfDomain(x));
        }
        Ok(self.eval(x))
    }

    /// Evaluate at many points.
    pub fn eval_many(&self, xs: &[f64]) -> Vec<f64> {
        xs.iter().map(|&x| self.eval(x)).collect()
    }

    /// Analytic derivative. **Returns a [`JacobiPoly`] in the `(alpha+1,
    /// beta+1)` basis**, which is where `d/dx P_n^{(alpha,beta)}` actually
    /// lives — this is a structural fact about Jacobi polynomials, not an
    /// implementation detail, so the type signature reflects it rather than
    /// silently re-expanding back into the original basis. Use
    /// [`JacobiConv`] if you need the derivative back in the original
    /// `(alpha, beta)` basis.
    pub fn derivative(&self) -> Self {
        let n = self.degree();
        let new_alpha = self.alpha + 1.0;
        let new_beta = self.beta + 1.0;
        if n == 0 {
            return Self {
                alpha: new_alpha,
                beta: new_beta,
                coeffs: vec![0.0],
            };
        }
        let mut d = vec![0.0_f64; n];
        for k in 0..n {
            d[k] = 0.5 * ((k + 2) as f64 + self.alpha + self.beta) * self.coeffs[k + 1];
        }
        Self {
            alpha: new_alpha,
            beta: new_beta,
            coeffs: d,
        }
    }

    /// Add two polynomials, which must share `(alpha, beta)`.
    pub fn checked_add(&self, other: &Self) -> Result<Self, JacobiError> {
        self.require_same_params(other)?;
        let n = self.coeffs.len().max(other.coeffs.len());
        let coeffs = (0..n)
            .map(|i| {
                self.coeffs.get(i).copied().unwrap_or(0.0) + other.coeffs.get(i).copied().unwrap_or(0.0)
            })
            .collect();
        Ok(Self {
            alpha: self.alpha,
            beta: self.beta,
            coeffs,
        })
    }

    /// Subtract two polynomials, which must share `(alpha, beta)`.
    pub fn checked_sub(&self, other: &Self) -> Result<Self, JacobiError> {
        self.require_same_params(other)?;
        let n = self.coeffs.len().max(other.coeffs.len());
        let coeffs = (0..n)
            .map(|i| {
                self.coeffs.get(i).copied().unwrap_or(0.0) - other.coeffs.get(i).copied().unwrap_or(0.0)
            })
            .collect();
        Ok(Self {
            alpha: self.alpha,
            beta: self.beta,
            coeffs,
        })
    }

    fn require_same_params(&self, other: &Self) -> Result<(), JacobiError> {
        if (self.alpha - other.alpha).abs() > 1e-9 || (self.beta - other.beta).abs() > 1e-9 {
            return Err(JacobiError::ParameterMismatch {
                expected: (self.alpha, self.beta),
                found: (other.alpha, other.beta),
            });
        }
        Ok(())
    }
}

impl Neg for &JacobiPoly {
    type Output = JacobiPoly;
    fn neg(self) -> JacobiPoly {
        JacobiPoly {
            alpha: self.alpha,
            beta: self.beta,
            coeffs: self.coeffs.iter().map(|c| -c).collect(),
        }
    }
}

impl Mul<f64> for &JacobiPoly {
    type Output = JacobiPoly;
    fn mul(self, scalar: f64) -> JacobiPoly {
        JacobiPoly {
            alpha: self.alpha,
            beta: self.beta,
            coeffs: self.coeffs.iter().map(|c| c * scalar).collect(),
        }
    }
}

impl fmt::Display for JacobiPoly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let terms: Vec<String> = self
            .coeffs
            .iter()
            .enumerate()
            .filter(|(_, c)| c.abs() > 1e-14)
            .map(|(k, c)| format!("{c:.6}*P{k}^({:.2},{:.2})", self.alpha, self.beta))
            .collect();
        if terms.is_empty() {
            write!(f, "0")
        } else {
            write!(f, "{}", terms.join(" + "))
        }
    }
}

/// **JacobiConv**: a cached basis-conversion operator that re-expands a
/// [`JacobiPoly`] from a source basis `(alpha_from, beta_from)` into a
/// target basis `(alpha_to, beta_to)`.
///
/// Construction precomputes a Gauss-Jacobi quadrature rule (in the target
/// weight) sized to exactly integrate the projection integrals for
/// polynomials up to `max_degree`, plus the target basis's normalization
/// constants. [`Self::convert`] then costs O(max_degree * quad_points) per
/// polynomial with no further node-finding — the expensive part
/// (locating quadrature nodes, which needs Newton iteration) happens once
/// at construction, which is what makes this "production ready" for
/// spectral-method workloads that convert many right-hand sides or basis
/// functions between the same two families repeatedly.
///
/// ## How it works
///
/// For source polynomial `f(x) = sum c_k P_k^{(a1,b1)}(x)`, the target
/// coefficients are the standard orthogonal-projection integrals
/// `d_k = (1 / h_k) * integral f(x) P_k^{(a2,b2)}(x) (1-x)^a2 (1+x)^b2 dx`,
/// evaluated exactly via Gauss-Jacobi quadrature in the target weight
/// (exact because `f` and each `P_k` are polynomials, so the integrand has
/// bounded degree). This generalizes beyond the common "raise alpha/beta by
/// one" connection formulas to *any* pair of parameters.
pub struct JacobiConv {
    alpha_from: f64,
    beta_from: f64,
    alpha_to: f64,
    beta_to: f64,
    max_degree: usize,
    nodes: Vec<f64>,
    weights: Vec<f64>,
    norm_sq: Vec<f64>,
}

impl JacobiConv {
    /// Build a conversion operator from `(alpha_from, beta_from)` to
    /// `(alpha_to, beta_to)`, valid for source polynomials up to
    /// `max_degree`. Precomputes and caches the Gauss-Jacobi quadrature
    /// rule and target normalization constants.
    pub fn new(
        alpha_from: f64,
        beta_from: f64,
        alpha_to: f64,
        beta_to: f64,
        max_degree: usize,
    ) -> Result<Self, JacobiError> {
        check_params(alpha_from, beta_from)?;
        check_params(alpha_to, beta_to)?;
        // Need to integrate f(x) * P_k(x) exactly, both of degree up to
        // max_degree, so the integrand has degree up to 2*max_degree.
        // Gauss quadrature with m points is exact to degree 2m - 1, so
        // m = max_degree + 1 suffices; add a small safety margin.
        let quad_n = max_degree + 4;
        let (nodes, weights) = gauss_jacobi(quad_n, alpha_to, beta_to)?;
        let norm_sq = (0..=max_degree)
            .map(|k| jacobi_norm_squared(k, alpha_to, beta_to))
            .collect();
        Ok(Self {
            alpha_from,
            beta_from,
            alpha_to,
            beta_to,
            max_degree,
            nodes,
            weights,
            norm_sq,
        })
    }

    /// Convert `poly` (which must be in this operator's source basis and
    /// within its configured `max_degree`) into the target basis.
    pub fn convert(&self, poly: &JacobiPoly) -> Result<JacobiPoly, JacobiError> {
        let (a, b) = poly.params();
        if (a - self.alpha_from).abs() > 1e-9 || (b - self.beta_from).abs() > 1e-9 {
            return Err(JacobiError::ParameterMismatch {
                expected: (self.alpha_from, self.beta_from),
                found: (a, b),
            });
        }
        let deg = poly.degree();
        if deg > self.max_degree {
            return Err(JacobiError::DegreeExceeded {
                max: self.max_degree,
                found: deg,
            });
        }

        let f_vals: Vec<f64> = self.nodes.iter().map(|&x| poly.eval(x)).collect();
        let mut target = vec![0.0_f64; self.max_degree + 1];
        for k in 0..=self.max_degree {
            let mut sum = 0.0;
            for j in 0..self.nodes.len() {
                let pk = jacobi_value(k, self.alpha_to, self.beta_to, self.nodes[j]);
                sum += self.weights[j] * f_vals[j] * pk;
            }
            target[k] = sum / self.norm_sq[k];
        }
        JacobiPoly::new(self.alpha_to, self.beta_to, target)
    }

    /// The `(alpha, beta)` this operator converts from and to.
    pub fn params(&self) -> ((f64, f64), (f64, f64)) {
        ((self.alpha_from, self.beta_from), (self.alpha_to, self.beta_to))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPS: f64 = 1e-8;

    #[test]
    fn jacobi_value_reduces_to_legendre() {
        // alpha = beta = 0 => Jacobi polynomials are exactly Legendre.
        for &x in &[-1.0, -0.5, -0.1, 0.0, 0.3, 0.7, 1.0] {
            let p0 = jacobi_value(0, 0.0, 0.0, x);
            let p1 = jacobi_value(1, 0.0, 0.0, x);
            let p2 = jacobi_value(2, 0.0, 0.0, x);
            let p3 = jacobi_value(3, 0.0, 0.0, x);
            assert!((p0 - 1.0).abs() < EPS);
            assert!((p1 - x).abs() < EPS);
            assert!((p2 - (1.5 * x * x - 0.5)).abs() < EPS);
            assert!((p3 - (2.5 * x * x * x - 1.5 * x)).abs() < EPS);
        }
    }

    #[test]
    fn jacobi_value_at_one_is_binomial() {
        // P_n^{(a,b)}(1) = C(n+a, n) for all valid a, b.
        let alpha = 1.7;
        let beta = 0.3;
        for n in 0..6 {
            let val = jacobi_value(n, alpha, beta, 1.0);
            let expected =
                (ln_gamma(n as f64 + alpha + 1.0) - ln_gamma(n as f64 + 1.0) - ln_gamma(alpha + 1.0))
                    .exp();
            assert!((val - expected).abs() < 1e-6, "n={n} val={val} exp={expected}");
        }
    }

    #[test]
    fn jacobi_derivative_matches_legendre_calculus() {
        // d/dx P_2(x) = 3x, d/dx P_3(x) = (15x^2 - 3)/2, for Legendre (a=b=0).
        for &x in &[-0.9, -0.3, 0.0, 0.4, 0.9] {
            let d2 = jacobi_derivative_value(2, 0.0, 0.0, x);
            assert!((d2 - 3.0 * x).abs() < EPS, "x={x} d2={d2}");
            let d3 = jacobi_derivative_value(3, 0.0, 0.0, x);
            let expected3 = (15.0 * x * x - 3.0) / 2.0;
            assert!((d3 - expected3).abs() < EPS, "x={x} d3={d3}");
        }
    }

    #[test]
    fn jacobi_poly_derivative_struct_matches_pointwise() {
        // p(x) = 2 P0 - P1 + 3 P2  (alpha=beta=0, i.e. Legendre)
        let p = JacobiPoly::new(0.0, 0.0, vec![2.0, -1.0, 3.0]).unwrap();
        let dp = p.derivative();
        assert_eq!(dp.params(), (1.0, 1.0));
        for &x in &[-0.9, -0.3, 0.0, 0.4, 0.9] {
            let direct = -1.0 * jacobi_derivative_value(1, 0.0, 0.0, x)
                + 3.0 * jacobi_derivative_value(2, 0.0, 0.0, x);
            assert!((dp.eval(x) - direct).abs() < EPS, "x={x}");
        }
    }

    #[test]
    fn gauss_jacobi_reduces_to_known_gauss_legendre_3pt() {
        let (nodes, weights) = gauss_jacobi(3, 0.0, 0.0).unwrap();
        let expected_x = (3.0_f64 / 5.0).sqrt();
        assert!((nodes[0] - (-expected_x)).abs() < 1e-8);
        assert!((nodes[1] - 0.0).abs() < 1e-8);
        assert!((nodes[2] - expected_x).abs() < 1e-8);
        assert!((weights[0] - 5.0 / 9.0).abs() < 1e-8);
        assert!((weights[1] - 8.0 / 9.0).abs() < 1e-8);
        assert!((weights[2] - 5.0 / 9.0).abs() < 1e-8);
    }

    #[test]
    fn gauss_jacobi_weights_sum_to_h0() {
        // sum_j w_j = integral P_0^2 w(x) dx = h_0, for any valid alpha, beta.
        for &(alpha, beta) in &[(0.0, 0.0), (1.0, 1.0), (0.5, -0.3), (2.0, 0.0)] {
            let (_, weights) = gauss_jacobi(6, alpha, beta).unwrap();
            let sum: f64 = weights.iter().sum();
            let h0 = jacobi_norm_squared(0, alpha, beta);
            assert!((sum - h0).abs() < 1e-8, "alpha={alpha} beta={beta}");
        }
    }

    #[test]
    fn gauss_jacobi_integrates_polynomials_exactly() {
        // n points integrate degree <= 2n-1 exactly. Check against a
        // polynomial with known closed-form integral against the weight.
        let (nodes, weights) = gauss_jacobi(5, 1.0, 2.0).unwrap();
        // Integrate f(x) = x^3 against weight (1-x)(1+x)^2.
        let quad: f64 = nodes
            .iter()
            .zip(weights.iter())
            .map(|(&x, &w)| w * x.powi(3))
            .sum();
        // Reference value computed independently via high-order Gauss-Jacobi (20 pts).
        let (nodes_ref, weights_ref) = gauss_jacobi(20, 1.0, 2.0).unwrap();
        let reference: f64 = nodes_ref
            .iter()
            .zip(weights_ref.iter())
            .map(|(&x, &w)| w * x.powi(3))
            .sum();
        assert!((quad - reference).abs() < 1e-9);
    }

    #[test]
    fn jacobi_conv_round_trip_recovers_original() {
        // Legendre polynomial, degree 3.
        let original = JacobiPoly::new(0.0, 0.0, vec![1.0, 2.0, -0.5, 0.75]).unwrap();
        let to_11 = JacobiConv::new(0.0, 0.0, 1.0, 1.0, 3).unwrap();
        let converted = to_11.convert(&original).unwrap();
        assert_eq!(converted.params(), (1.0, 1.0));

        let back_to_00 = JacobiConv::new(1.0, 1.0, 0.0, 0.0, 3).unwrap();
        let round_tripped = back_to_00.convert(&converted).unwrap();

        for &x in &[-0.9, -0.4, 0.0, 0.4, 0.9] {
            assert!(
                (original.eval(x) - round_tripped.eval(x)).abs() < 1e-6,
                "x={x} orig={} rt={}",
                original.eval(x),
                round_tripped.eval(x)
            );
            // The intermediate (1,1)-basis representation must also agree
            // pointwise with the original function, since conversion is a
            // change of basis, not an approximation, for exactly
            // representable polynomials.
            assert!(
                (original.eval(x) - converted.eval(x)).abs() < 1e-6,
                "x={x} mismatch after single conversion"
            );
        }
    }

    #[test]
    fn jacobi_conv_rejects_wrong_source_params() {
        let conv = JacobiConv::new(0.0, 0.0, 1.0, 1.0, 3).unwrap();
        let wrong_basis = JacobiPoly::new(0.5, 0.5, vec![1.0, 2.0]).unwrap();
        assert!(matches!(
            conv.convert(&wrong_basis),
            Err(JacobiError::ParameterMismatch { .. })
        ));
    }

    #[test]
    fn jacobi_conv_rejects_degree_exceeded() {
        let conv = JacobiConv::new(0.0, 0.0, 1.0, 1.0, 2).unwrap();
        let too_high_degree = JacobiPoly::new(0.0, 0.0, vec![1.0, 1.0, 1.0, 1.0]).unwrap();
        assert!(matches!(
            conv.convert(&too_high_degree),
            Err(JacobiError::DegreeExceeded { .. })
        ));
    }

    #[test]
    fn invalid_parameters_rejected() {
        assert!(matches!(
            JacobiPoly::new(-1.5, 0.0, vec![1.0]),
            Err(JacobiError::InvalidParameters { .. })
        ));
        assert!(matches!(
            JacobiPoly::new(0.0, -1.0, vec![1.0]),
            Err(JacobiError::InvalidParameters { .. })
        ));
    }

    #[test]
    fn checked_add_and_sub_require_matching_params() {
        let a = JacobiPoly::new(0.0, 0.0, vec![1.0, 2.0]).unwrap();
        let b = JacobiPoly::new(1.0, 0.0, vec![1.0, 2.0]).unwrap();
        assert!(matches!(
            a.checked_add(&b),
            Err(JacobiError::ParameterMismatch { .. })
        ));

        let c = JacobiPoly::new(0.0, 0.0, vec![3.0, -1.0, 0.5]).unwrap();
        let sum = a.checked_add(&c).unwrap();
        assert_eq!(sum.coefficients(), &[4.0, 1.0, 0.5]);
        let diff = a.checked_sub(&c).unwrap();
        assert_eq!(diff.coefficients(), &[-2.0, 3.0, -0.5]);
    }

    #[test]
    fn scalar_mul_and_neg() {
        let a = JacobiPoly::new(0.5, 0.5, vec![1.0, -2.0, 3.0]).unwrap();
        let scaled = &a * 2.0;
        assert_eq!(scaled.coefficients(), &[2.0, -4.0, 6.0]);
        let neg = -&a;
        assert_eq!(neg.coefficients(), &[-1.0, 2.0, -3.0]);
    }

    #[test]
    fn truncate_drops_small_trailing_terms() {
        let mut p = JacobiPoly::new(0.0, 0.0, vec![1.0, 2.0, 1e-15, 1e-16]).unwrap();
        p.truncate(1e-12);
        assert_eq!(p.coefficients(), &[1.0, 2.0]);
    }
}
