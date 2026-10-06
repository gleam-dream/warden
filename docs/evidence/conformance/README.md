# OpenID RP conformance receipts

- `summary.json` and `run-log.txt` hold the native-backend receipt. `history/`
  holds the removed-backend receipts. Their interpretation, run options, results
  and limitations live in [ADR 0008](../../adr/0008-oracles-and-evidence-limits.md).
- The fixture uses OpenID Foundation `release-v5.3.1`, revision
  `440eec8bac7b12b7389d7ca9cbc459b53507a443` (MIT). Compose configuration and
  `test/conformance/run.mjs` retain the exact inputs and executable harness.
- Start with `scripts/conformance-suite up`, then run `scripts/conformance`
  against the reference consumer. The harness generates disposable test PKI,
  verifies suite TLS and writes module details under `build/conformance/`.
- Retain new raw output with exact package, fixture and option revisions. Report
  skipped and human-review modules separately. A local receipt is regression
  evidence and cannot certify a release.
- See [TESTING.md](../../TESTING.md) for operating commands. ADR 0008 records
  coverage gaps without presenting older failures as current implementation
  findings.
