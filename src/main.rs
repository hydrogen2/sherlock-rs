//! sherlock-rs CLI — hunt usernames across ~480 sites.
//!
//! A faithful, single-binary Rust port of sherlock. Detection semantics live in the
//! library (`detect`/`engine`); this file is just argument parsing and printing.

use std::time::Duration;

use clap::Parser;
use sherlock_rs::engine::{self, EngineOptions};
use sherlock_rs::result::QueryStatus;
use sherlock_rs::site::{self, Manifest};

#[derive(Parser, Debug)]
#[command(
    name = "sherlock-rs",
    about = "Hunt down social media accounts by username across social networks (Rust port).",
    version
)]
struct Args {
    /// One or more usernames to check.
    #[arg(required = true, value_name = "USERNAME")]
    usernames: Vec<String>,

    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 60)]
    timeout: u64,

    /// Maximum number of concurrent requests.
    #[arg(long, default_value_t = 20)]
    concurrency: usize,

    /// Restrict the search to these sites (case-insensitive, repeatable).
    #[arg(long = "site", value_name = "SITE")]
    sites: Vec<String>,

    /// Include NSFW sites (skipped by default).
    #[arg(long)]
    nsfw: bool,

    /// Also print sites where the username was not found / errored.
    #[arg(long)]
    print_all: bool,

    /// Route requests through this proxy (e.g. socks5://127.0.0.1:9050).
    #[arg(long)]
    proxy: Option<String>,
}

/// Build the working set of sites from CLI filters.
fn select_sites(manifest: &Manifest, args: &Args) -> Manifest {
    let wanted: Vec<String> = args.sites.iter().map(|s| s.to_lowercase()).collect();
    manifest
        .iter()
        .filter(|(name, site)| {
            if !args.nsfw && site.is_nsfw {
                return false;
            }
            if !wanted.is_empty() && !wanted.contains(&name.to_lowercase()) {
                return false;
            }
            true
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let manifest = site::load_embedded()?;
    let sites = select_sites(&manifest, &args);

    if sites.is_empty() {
        anyhow::bail!("no sites selected (check --site names / --nsfw)");
    }

    let opts = EngineOptions {
        timeout: Duration::from_secs(args.timeout),
        max_workers: args.concurrency,
        proxy: args.proxy.clone(),
    };

    for username in &args.usernames {
        println!("[*] Checking username {username} on {} sites", sites.len());
        let results = engine::run(&sites, username, &opts).await?;

        let mut found = 0usize;
        for r in &results {
            match r.status {
                QueryStatus::Claimed => {
                    found += 1;
                    println!("[+] {}: {}", r.site_name, r.site_url_user);
                }
                _ if args.print_all => {
                    let note = r.context.clone().unwrap_or_else(|| r.status.to_string());
                    println!("[-] {}: {}", r.site_name, note);
                }
                _ => {}
            }
        }
        println!("[*] Found {username} on {found} sites\n");
    }

    Ok(())
}
