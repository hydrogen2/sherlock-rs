# Deviations from upstream sherlock

This port stays faithful to upstream detection semantics. Where we knowingly differ
from the upstream `data.json` / behavior, we record it here so it stays honest and
so each item can be offered back upstream as a good-faith PR.

## Data fixes

- **Pinterest — removed stray `errorUrl`.** Upstream's `Pinterest` entry uses
  `errorType: status_code` but also carries an `errorUrl`, which is only meaningful
  for `response_url` detection. This makes the entry fail upstream's *own*
  `data.schema.json` (confirmed with both Python `jsonschema` and Rust `jsonschema`).
  The field is never read by the detection logic, so removing it changes no behavior
  and makes our manifest schema-valid. **Candidate upstream PR.**
