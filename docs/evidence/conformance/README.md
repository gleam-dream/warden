# OpenID RP conformance receipts

Raw receipts of selected OpenID Foundation relying-party plans: `summary.json` and
`run-log.txt` for the native backend, `history/` for earlier receipts. The suite
pin, outcome classification, deliberate differences and limits are in
[ORACLE.md](../../ORACLE.md); [ADR 0008](../../adr/0008-oracles-and-evidence-limits.md)
interprets the receipts.

- Run `scripts/conformance-suite up`, then `scripts/conformance`. Output goes under `build/conformance/`.
- A local receipt is regression evidence and does not certify a release.
