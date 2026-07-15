//! Query status + result types — the Rust equivalent of upstream `result.py`.
//!
//! Rust lesson: an `enum` here is a true sum type. Unlike Java, where you'd reach
//! for an `enum` class or constants, a Rust enum can carry data per-variant and the
//! compiler forces every `match` to handle every case — so adding a status later
//! makes the code fail to compile until you handle it everywhere. That is a feature.

use std::fmt;

/// Outcome of checking one username against one site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryStatus {
    /// Username detected on the site.
    Claimed,
    /// Username not detected (i.e. available).
    Available,
    /// An error occurred while trying to detect the username.
    Unknown,
    /// Username is not allowable for this site (failed `regexCheck`).
    Illegal,
    /// Request was blocked by a WAF (e.g. Cloudflare).
    Waf,
}

impl fmt::Display for QueryStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Mirrors the upstream string values so output stays comparable.
        let s = match self {
            QueryStatus::Claimed => "Claimed",
            QueryStatus::Available => "Available",
            QueryStatus::Unknown => "Unknown",
            QueryStatus::Illegal => "Illegal",
            QueryStatus::Waf => "WAF",
        };
        f.write_str(s)
    }
}

/// Full result for one (username, site) query.
#[derive(Debug, Clone)]
pub struct QueryResult {
    pub username: String,
    pub site_name: String,
    /// URL the user *would* live at if the account exists.
    pub site_url_user: String,
    pub status: QueryStatus,
    pub query_time: Option<std::time::Duration>,
    /// Extra context, e.g. the error kind when status is `Unknown`.
    pub context: Option<String>,
}

impl fmt::Display for QueryResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.context {
            Some(ctx) => write!(f, "{} ({})", self.status, ctx),
            None => write!(f, "{}", self.status),
        }
    }
}
