//! The site manifest — Rust types that deserialize `resources/data.json`.
//!
//! Rust lesson: `serde` derives (de)serialization at compile time from the struct
//! shape. Fields map by name; `#[serde(rename)]` bridges the camelCase JSON to
//! snake_case Rust. The `OneOrMany` enum below shows off `#[serde(untagged)]`:
//! serde tries each variant in order and keeps the first that fits, which is how
//! we accept `errorMsg` being *either* a string or a list of strings.

use serde::Deserialize;
use std::collections::BTreeMap;

/// A field that may appear in the manifest as a single value or a list of them.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T: Clone> OneOrMany<T> {
    /// Normalize to a slice-friendly `Vec` so callers don't branch on the shape.
    pub fn to_vec(&self) -> Vec<T> {
        match self {
            OneOrMany::One(v) => vec![v.clone()],
            OneOrMany::Many(v) => v.clone(),
        }
    }
}

/// How a site signals "this username does not exist".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum ErrorType {
    #[serde(rename = "status_code")]
    StatusCode,
    #[serde(rename = "message")]
    Message,
    #[serde(rename = "response_url")]
    ResponseUrl,
}

/// One site's detection recipe (one entry in `data.json`).
#[derive(Debug, Clone, Deserialize)]
pub struct Site {
    pub url: String,
    #[serde(rename = "urlMain")]
    pub url_main: String,
    #[serde(rename = "errorType")]
    pub error_type: ErrorType,
    pub username_claimed: Option<String>,

    #[serde(rename = "errorMsg", default)]
    pub error_msg: Option<OneOrMany<String>>,
    #[serde(rename = "errorCode", default)]
    pub error_code: Option<OneOrMany<i64>>,
    #[serde(rename = "errorUrl", default)]
    pub error_url: Option<String>,
    #[serde(rename = "regexCheck", default)]
    pub regex_check: Option<String>,
    #[serde(rename = "urlProbe", default)]
    pub url_probe: Option<String>,
    #[serde(rename = "request_method", default)]
    pub request_method: Option<String>,
    #[serde(rename = "request_payload", default)]
    pub request_payload: Option<serde_json::Value>,
    #[serde(default)]
    pub headers: Option<BTreeMap<String, String>>,
    #[serde(rename = "isNSFW", default)]
    pub is_nsfw: bool,
}

/// The whole manifest: site name -> recipe. `BTreeMap` keeps sites in a stable
/// (alphabetical) order so output and tests are deterministic run to run.
pub type Manifest = BTreeMap<String, Site>;

/// Parse a manifest from JSON text, dropping the leading `$schema` metadata key.
pub fn parse_manifest(json: &str) -> anyhow::Result<Manifest> {
    // The file is an object of {name: site, ..} plus a "$schema" string entry.
    // Deserialize loosely first, then keep only the real site objects.
    let raw: BTreeMap<String, serde_json::Value> = serde_json::from_str(json)?;
    let mut manifest = Manifest::new();
    for (name, value) in raw {
        if name.starts_with('$') {
            continue; // "$schema"
        }
        let site: Site =
            serde_json::from_value(value).map_err(|e| anyhow::anyhow!("site {name:?}: {e}"))?;
        manifest.insert(name, site);
    }
    Ok(manifest)
}

/// The manifest bundled into the binary at compile time — no data file to ship.
///
/// Rust lesson: `include_str!` embeds the file contents as a `&'static str` in the
/// executable. That is how the port becomes a single self-contained binary, a real
/// UX win over the Python tool which loads `data.json` from disk at runtime.
pub const EMBEDDED_MANIFEST: &str = include_str!("../resources/data.json");

/// Load the embedded manifest.
pub fn load_embedded() -> anyhow::Result<Manifest> {
    parse_manifest(EMBEDDED_MANIFEST)
}
