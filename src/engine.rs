//! The network engine — the I/O edge that wraps the pure core in [`crate::detect`].
//!
//! Rust/async lesson: `reqwest`'s redirect policy is set per-*client*, not per-request,
//! and only `response_url` detection needs redirects off. So we build two clients up
//! front (redirects on / off) and pick one per site. Concurrency is a bounded
//! `buffer_unordered` stream — the async analogue of upstream's 20-worker thread pool,
//! but without OS threads: thousands of in-flight requests would still map onto a
//! handful of tokio worker threads.

use crate::detect::{decide, plan_request, profile_url, HttpMethod, PlanOutcome};
use crate::result::{QueryResult, QueryStatus};
use crate::site::{Manifest, Site};
use futures::stream::{self, StreamExt};
use reqwest::redirect::Policy;
use reqwest::{Client, Method};
use std::time::{Duration, Instant};

const DEFAULT_UA: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0";

/// Tunables for a run.
pub struct EngineOptions {
    pub timeout: Duration,
    pub max_workers: usize,
    pub proxy: Option<String>,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(60),
            max_workers: 20,
            proxy: None,
        }
    }
}

/// One client with redirects allowed, one without — reused across all sites.
struct Clients {
    redirect: Client,
    no_redirect: Client,
}

fn build_client(allow_redirects: bool, opts: &EngineOptions) -> reqwest::Result<Client> {
    let mut b = Client::builder()
        .timeout(opts.timeout)
        .redirect(if allow_redirects {
            Policy::default()
        } else {
            Policy::none()
        });
    if let Some(p) = &opts.proxy {
        b = b.proxy(reqwest::Proxy::all(p)?);
    }
    b.build()
}

fn to_method(m: HttpMethod) -> Method {
    match m {
        HttpMethod::Get => Method::GET,
        HttpMethod::Head => Method::HEAD,
        HttpMethod::Post => Method::POST,
        HttpMethod::Put => Method::PUT,
    }
}

/// Human-readable label for a network failure, echoing upstream's error contexts.
fn classify_error(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "Timeout Error".into()
    } else if e.is_connect() {
        "Error Connecting".into()
    } else if e.is_redirect() {
        "Redirect Error".into()
    } else {
        format!("Request Error: {e}")
    }
}

/// Check one username against one site. Never panics: any failure becomes `Unknown`.
async fn check_one(clients: &Clients, site_name: &str, site: &Site, username: &str) -> QueryResult {
    let base = QueryResult {
        username: username.to_string(),
        site_name: site_name.to_string(),
        site_url_user: profile_url(site, username),
        status: QueryStatus::Unknown,
        query_time: None,
        context: None,
    };

    let plan = match plan_request(site, username) {
        Ok(PlanOutcome::Fetch(p)) => p,
        Ok(PlanOutcome::Skip(status)) => return QueryResult { status, ..base },
        // A malformed manifest entry (bad regex/method): report, don't crash the run.
        Err(e) => {
            return QueryResult {
                status: QueryStatus::Unknown,
                context: Some(format!("Manifest error: {e}")),
                ..base
            }
        }
    };

    let client = if plan.allow_redirects {
        &clients.redirect
    } else {
        &clients.no_redirect
    };

    let mut req = client
        .request(to_method(plan.method), &plan.probe_url)
        .header("User-Agent", DEFAULT_UA);
    for (k, v) in &plan.extra_headers {
        req = req.header(k, v);
    }
    if let Some(payload) = &plan.payload {
        req = req.json(payload);
    }

    let start = Instant::now();
    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            // Body is empty for HEAD (status_code sites), which `decide` handles.
            let body = resp.text().await.unwrap_or_default();
            QueryResult {
                status: decide(site, status, &body),
                query_time: Some(start.elapsed()),
                ..base
            }
        }
        Err(e) => QueryResult {
            status: QueryStatus::Unknown,
            query_time: Some(start.elapsed()),
            context: Some(classify_error(&e)),
            ..base
        },
    }
}

/// Check `username` across every site in `manifest`, up to `max_workers` at a time.
/// Results come back in manifest (alphabetical) order regardless of completion order.
pub async fn run(
    manifest: &Manifest,
    username: &str,
    opts: &EngineOptions,
) -> anyhow::Result<Vec<QueryResult>> {
    let clients = Clients {
        redirect: build_client(true, opts)?,
        no_redirect: build_client(false, opts)?,
    };

    let mut results: Vec<QueryResult> = stream::iter(manifest.iter())
        .map(|(name, site)| {
            let clients = &clients;
            async move { check_one(clients, name, site, username).await }
        })
        .buffer_unordered(opts.max_workers)
        .collect()
        .await;

    results.sort_by(|a, b| a.site_name.cmp(&b.site_name));
    Ok(results)
}
