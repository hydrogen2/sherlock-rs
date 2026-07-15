//! Pure detection logic — no network here, by design.
//!
//! Upstream `sherlock.py` interleaves building the request, firing it, and judging
//! the response in one 200-line function, so its detection rules can only be tested
//! by hitting live sites. We split that in two:
//!
//!   * [`plan_request`] turns a [`Site`] + username into *what to fetch* (or a
//!     decision to skip), and
//!   * [`decide`] turns *an already-fetched response* into a [`QueryStatus`].
//!
//! Both are pure functions, so the whole detection contract is covered by fast,
//! deterministic unit tests (bottom of this file) with zero network.

use crate::result::QueryStatus;
use crate::site::{ErrorType, Site};
// fancy-regex, not `regex`: several sites' `regexCheck` use look-around (e.g. GitHub's
// `-(?=[a-zA-Z0-9])`), which the `regex` crate rejects. fancy-regex is a superset that
// matches Python `re` semantics for these patterns.
use fancy_regex::Regex;

/// WAF fingerprints — if any appears in the body, the request was blocked rather
/// than answered, so the result is neither claimed nor available. Ported verbatim
/// from upstream (keep the trailing date comments so provenance stays clear).
pub const WAF_FINGERPRINTS: &[&str] = &[
    // 2024-05-13 Cloudflare
    r#".loading-spinner{visibility:hidden}body.no-js .challenge-running{display:none}body.dark{background-color:#222;color:#d9d9d9}body.dark a{color:#fff}body.dark a:hover{color:#ee730a;text-decoration:underline}body.dark .lds-ring div{border-color:#999 transparent transparent}body.dark .font-red{color:#b20f03}body.dark"#,
    // 2024-11-11 Cloudflare error page
    r#"<span id="challenge-error-text">"#,
    // 2024-11-11 Cloudfront (AWS)
    r#"AwsWafIntegration.forceRefreshToken"#,
    // 2024-04-09 PerimeterX / Human Security
    r#"{return l.onPageView}}),Object.defineProperty(r,"perimeterxIdentifiers",{enumerable:"#,
];

/// The HTTP verb a site needs. Kept independent of the HTTP client so this module
/// stays network-free; the engine maps it onto `reqwest::Method`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Head,
    Post,
    Put,
}

/// What to fetch for a site, once we've decided the username is even allowed.
#[derive(Debug, Clone)]
pub struct RequestPlan {
    pub method: HttpMethod,
    /// URL actually probed (may differ from the human-facing profile URL).
    pub probe_url: String,
    /// Human-facing profile URL (what we report if the account exists).
    pub display_url: String,
    /// `false` only for `response_url` sites, where we must see the un-redirected code.
    pub allow_redirects: bool,
    /// Header overrides beyond the default User-Agent.
    pub extra_headers: Vec<(String, String)>,
    pub payload: Option<serde_json::Value>,
}

/// Outcome of planning: either fetch something, or skip with a final status.
#[derive(Debug, Clone)]
pub enum PlanOutcome {
    Fetch(RequestPlan),
    /// e.g. username failed `regexCheck` -> `Illegal`, no request made.
    Skip(QueryStatus),
}

/// Replace every `{}` in `template` with `value` (upstream `interpolate_string`).
fn interpolate(template: &str, value: &str) -> String {
    template.replace("{}", value)
}

/// The human-facing profile URL for `username` on `site` (spaces percent-encoded).
/// Shared by the planner and the engine so the reported URL is always consistent.
pub fn profile_url(site: &Site, username: &str) -> String {
    interpolate(&site.url, &username.replace(' ', "%20"))
}

/// Recursively interpolate `{}` inside a JSON payload's string values.
fn interpolate_value(v: &serde_json::Value, username: &str) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::String(s) => Value::String(interpolate(s, username)),
        Value::Array(a) => Value::Array(a.iter().map(|x| interpolate_value(x, username)).collect()),
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, x)| (k.clone(), interpolate_value(x, username)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Decide *what to fetch* for `site` given `username`, or that we should skip it.
///
/// Returns `Err` only on a malformed manifest (bad regex or unknown method) — those
/// are studio bugs to surface, not per-user outcomes.
pub fn plan_request(site: &Site, username: &str) -> anyhow::Result<PlanOutcome> {
    // regexCheck gates whether the username is even valid for this site.
    if let Some(pattern) = &site.regex_check {
        let re =
            Regex::new(pattern).map_err(|e| anyhow::anyhow!("bad regexCheck {pattern:?}: {e}"))?;
        // fancy-regex's is_match returns Result (backtracking can fail); a runtime
        // failure is a manifest problem to surface, not a silent skip.
        let matched = re
            .is_match(username)
            .map_err(|e| anyhow::anyhow!("regexCheck runtime error {pattern:?}: {e}"))?;
        if !matched {
            return Ok(PlanOutcome::Skip(QueryStatus::Illegal));
        }
    }

    // The profile URL encodes spaces; the probe URL (if distinct) uses the raw name,
    // matching upstream's exact behavior.
    let display_url = profile_url(site, username);
    let probe_url = match &site.url_probe {
        None => display_url.clone(),
        Some(p) => interpolate(p, username),
    };

    let method = match site.request_method.as_deref() {
        Some("GET") => HttpMethod::Get,
        Some("HEAD") => HttpMethod::Head,
        Some("POST") => HttpMethod::Post,
        Some("PUT") => HttpMethod::Put,
        Some(other) => anyhow::bail!("unsupported request_method {other:?} for {}", site.url),
        // Default: status_code sites need only headers, everything else needs the body.
        None => match site.error_type {
            ErrorType::StatusCode => HttpMethod::Head,
            _ => HttpMethod::Get,
        },
    };

    let extra_headers = site
        .headers
        .as_ref()
        .map(|h| h.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();

    let payload = site
        .request_payload
        .as_ref()
        .map(|p| interpolate_value(p, username));

    Ok(PlanOutcome::Fetch(RequestPlan {
        method,
        probe_url,
        display_url,
        // Only response_url detection needs redirects disabled.
        allow_redirects: site.error_type != ErrorType::ResponseUrl,
        extra_headers,
        payload,
    }))
}

/// Judge an already-fetched response. `status` is the HTTP code; `body` is the text
/// (may be empty for HEAD requests, which is fine for status-code detection).
///
/// This is a faithful port of upstream's decision ladder, minus the network glue.
pub fn decide(site: &Site, status: u16, body: &str) -> QueryStatus {
    // A WAF block masquerades as a normal page; catch it before anything else.
    if WAF_FINGERPRINTS.iter().any(|f| body.contains(f)) {
        return QueryStatus::Waf;
    }

    match site.error_type {
        ErrorType::Message => {
            // "error message present in body" == account does NOT exist.
            let errors = site
                .error_msg
                .as_ref()
                .map(|e| e.to_vec())
                .unwrap_or_default();
            let error_found = errors.iter().any(|e| body.contains(e.as_str()));
            if error_found {
                QueryStatus::Available
            } else {
                QueryStatus::Claimed
            }
        }
        ErrorType::StatusCode => {
            // 2xx means claimed, unless it matches an explicit not-found errorCode.
            if let Some(codes) = &site.error_code {
                if codes.to_vec().contains(&(status as i64)) {
                    return QueryStatus::Available;
                }
            }
            if (200..300).contains(&status) {
                QueryStatus::Claimed
            } else {
                QueryStatus::Available
            }
        }
        ErrorType::ResponseUrl => {
            // Redirects were disabled: a clean 2xx on the original URL == claimed.
            if (200..300).contains(&status) {
                QueryStatus::Claimed
            } else {
                QueryStatus::Available
            }
        }
    }
}

// --------------------------------------------------------------------------- //
// The detection oracle — deterministic, no network. Mirrors the semantics that
// upstream's online tests assert, but runs in milliseconds offline.
// --------------------------------------------------------------------------- //
#[cfg(test)]
mod tests {
    use super::*;
    use crate::site::{ErrorType, OneOrMany, Site};

    fn site(error_type: ErrorType) -> Site {
        Site {
            url: "https://x.test/{}".into(),
            url_main: "https://x.test/".into(),
            error_type,
            username_claimed: Some("blue".into()),
            error_msg: None,
            error_code: None,
            error_url: None,
            regex_check: None,
            url_probe: None,
            request_method: None,
            request_payload: None,
            headers: None,
            is_nsfw: false,
        }
    }

    #[test]
    fn message_error_present_means_available() {
        let mut s = site(ErrorType::Message);
        s.error_msg = Some(OneOrMany::One("user not found".into()));
        assert_eq!(
            decide(&s, 200, "... user not found ..."),
            QueryStatus::Available
        );
        assert_eq!(decide(&s, 200, "welcome, blue!"), QueryStatus::Claimed);
    }

    #[test]
    fn message_accepts_a_list_of_error_strings() {
        let mut s = site(ErrorType::Message);
        s.error_msg = Some(OneOrMany::Many(vec!["404".into(), "gone".into()]));
        assert_eq!(decide(&s, 200, "page is gone"), QueryStatus::Available);
        assert_eq!(decide(&s, 200, "all good"), QueryStatus::Claimed);
    }

    #[test]
    fn status_code_2xx_claimed_else_available() {
        let s = site(ErrorType::StatusCode);
        assert_eq!(decide(&s, 200, ""), QueryStatus::Claimed);
        assert_eq!(decide(&s, 404, ""), QueryStatus::Available);
        assert_eq!(decide(&s, 301, ""), QueryStatus::Available);
        assert_eq!(decide(&s, 199, ""), QueryStatus::Available);
    }

    #[test]
    fn status_code_explicit_error_code_wins() {
        let mut s = site(ErrorType::StatusCode);
        s.error_code = Some(OneOrMany::One(200));
        // 200 is the site's declared "not found" code -> available despite being 2xx.
        assert_eq!(decide(&s, 200, ""), QueryStatus::Available);
    }

    #[test]
    fn response_url_2xx_claimed() {
        let s = site(ErrorType::ResponseUrl);
        assert_eq!(decide(&s, 200, ""), QueryStatus::Claimed);
        assert_eq!(decide(&s, 302, ""), QueryStatus::Available);
        assert_eq!(decide(&s, 404, ""), QueryStatus::Available);
    }

    #[test]
    fn waf_fingerprint_beats_everything() {
        let s = site(ErrorType::StatusCode);
        let body = format!("<html>{}</html>", WAF_FINGERPRINTS[1]);
        assert_eq!(decide(&s, 200, &body), QueryStatus::Waf);
    }

    #[test]
    fn regexcheck_failure_is_illegal_and_skips() {
        let mut s = site(ErrorType::StatusCode);
        s.regex_check = Some("^[0-9]+$".into());
        match plan_request(&s, "not-a-number").unwrap() {
            PlanOutcome::Skip(QueryStatus::Illegal) => {}
            other => panic!("expected Skip(Illegal), got {other:?}"),
        }
        assert!(matches!(
            plan_request(&s, "12345").unwrap(),
            PlanOutcome::Fetch(_)
        ));
    }

    #[test]
    fn plan_defaults_method_and_redirects_by_error_type() {
        let head = plan_request(&site(ErrorType::StatusCode), "blue").unwrap();
        let get = plan_request(&site(ErrorType::Message), "blue").unwrap();
        let resp = plan_request(&site(ErrorType::ResponseUrl), "blue").unwrap();
        match (head, get, resp) {
            (PlanOutcome::Fetch(h), PlanOutcome::Fetch(g), PlanOutcome::Fetch(r)) => {
                assert_eq!(h.method, HttpMethod::Head);
                assert!(h.allow_redirects);
                assert_eq!(g.method, HttpMethod::Get);
                assert_eq!(r.method, HttpMethod::Get);
                assert!(!r.allow_redirects, "response_url must disable redirects");
            }
            _ => panic!("all three should plan a fetch"),
        }
    }

    #[test]
    fn regexcheck_supports_lookaround_like_github() {
        // GitHub's real pattern uses a look-ahead the `regex` crate can't compile.
        let mut s = site(ErrorType::StatusCode);
        s.regex_check = Some(r"^[a-zA-Z0-9](?:[a-zA-Z0-9]|-(?=[a-zA-Z0-9])){0,38}$".into());
        assert!(matches!(
            plan_request(&s, "torvalds").unwrap(),
            PlanOutcome::Fetch(_)
        ));
        // trailing hyphen is disallowed by the look-ahead -> Illegal
        assert!(matches!(
            plan_request(&s, "bad-").unwrap(),
            PlanOutcome::Skip(QueryStatus::Illegal)
        ));
    }

    #[test]
    fn plan_interpolates_username_and_encodes_spaces() {
        if let PlanOutcome::Fetch(p) =
            plan_request(&site(ErrorType::StatusCode), "john doe").unwrap()
        {
            assert_eq!(p.display_url, "https://x.test/john%20doe");
        } else {
            panic!("expected fetch");
        }
    }
}
