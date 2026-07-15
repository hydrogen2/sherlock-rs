//! sherlock-rs: hunt a username across ~480 sites. Library root.
//!
//! Module map:
//!   * [`site`]   — the manifest types + loader (`data.json`)
//!   * [`result`] — [`result::QueryStatus`] / [`result::QueryResult`]
//!   * [`detect`] — pure request-planning + response-judging (no network)
//!
//! The network engine + CLI build on these; keeping detection pure is what makes
//! the test suite fast and deterministic.

pub mod detect;
pub mod engine;
pub mod result;
pub mod site;
