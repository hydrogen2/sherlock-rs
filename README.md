# sherlock-rs

**Hunt down social media accounts by username across ~480 sites — as a single, fast, static binary.**

`sherlock-rs` is a faithful Rust port of the excellent
[sherlock-project/sherlock](https://github.com/sherlock-project/sherlock). It reuses
sherlock's battle-tested site manifest and detection semantics, but ships as one
self-contained binary — no Python, no virtualenv, no runtime data files.

> Full credit to the Sherlock Project and its contributors for the original tool and
> the site manifest this port builds on. sherlock-rs is a re-implementation, not a
> replacement — see [Attribution](#attribution).

## Why a port?

| | Python sherlock | **sherlock-rs** |
|---|---|---|
| Wall-clock, full scan¹ | ~39.5 s | **~27.4 s** (~1.4× faster) |
| Peak memory | ~510 MB | **~29 MB** (~17× less) |
| Ship it as | 129 MB venv + a Python | **8.6 MB static binary** |
| Detection rules | source of truth | ported 1:1, unit-tested |

¹ Two trials each, usernames `torvalds` and `jack`, `--timeout 15`, same machine and
network. Live results are inherently non-deterministic (rate limits, WAFs, timeouts);
numbers are representative, not guarantees. In both trials sherlock-rs also *found more
accounts* than Python — spot-checked as real accounts Python missed to timeouts, not
false positives.

## Install

```bash
# From crates.io (installs the `sherlock-rs` binary):
cargo install sherlock-hunt

# ...or from source:
cargo install --path .
```

> The crate is named `sherlock-hunt` on crates.io (the name `sherlock-rs` was already
> taken by an unrelated crate); the installed binary is still `sherlock-rs`.

## Usage

```bash
sherlock-rs torvalds                 # scan all sites
sherlock-rs torvalds jack            # multiple usernames
sherlock-rs torvalds --site GitHub --site Reddit
sherlock-rs torvalds --print-all     # also show not-found / errored
sherlock-rs torvalds --timeout 20 --concurrency 30
sherlock-rs torvalds --nsfw          # include NSFW sites (off by default)
sherlock-rs torvalds --proxy socks5://127.0.0.1:9050
```

Output marks found accounts with `[+]` and prints the profile URL.

## How it works

Each site in the manifest declares how to tell "this username exists" from a single
HTTP request. There are three detection strategies:

- **status_code** — a 2xx means the account exists (a `HEAD` request is enough).
- **message** — fetch the page; if a known "not found" string appears, it's available.
- **response_url** — with redirects disabled, a clean 2xx means it exists.

The port keeps a clean split the original doesn't: a **pure core** (`src/detect.rs`:
plan a request, judge a response) with **no network**, wrapped by an **async engine**
(`src/engine.rs`: reqwest + tokio, bounded concurrency). That's why the detection rules
are covered by fast, deterministic offline tests — run `cargo test`.

## Differences from upstream

Detection is intentionally 1:1. Knowing deviations (currently: one manifest bug-fix we
plan to send upstream) are tracked in [`UPSTREAM-DEVIATIONS.md`](UPSTREAM-DEVIATIONS.md).

## Attribution

This project is a derivative work of
[sherlock-project/sherlock](https://github.com/sherlock-project/sherlock), MIT-licensed.
The site manifest (`resources/data.json`) originates there; the original license is
preserved in [`resources/UPSTREAM-LICENSE`](resources/UPSTREAM-LICENSE). sherlock-rs is
released under the MIT license (see [`LICENSE`](LICENSE)).
