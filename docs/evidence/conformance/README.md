# OpenID RP conformance receipts

`summary.json` records the outcomes of selected OpenID Foundation relying-party
plans for the native backend. The historical summary is not a validation gate. The
run log and the removed backend's receipts are retained in repository history at
commit `afd4f25`. The suite pin, outcome classification, deliberate differences
and limits are in [ORACLE.md](../../ORACLE.md);
[ADR 0008](../../adr/0008-oracles-and-evidence-limits.md) interprets the receipt.

- Run `scripts/conformance-suite up`, then `scripts/conformance`. Output goes under `build/conformance/`.
- A local receipt is regression evidence and does not certify a release.
