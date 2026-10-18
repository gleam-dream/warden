# HTTP transport receipts

`logs/` holds the raw outputs of the retained HTTP Gun adoption experiment.
[ADR 0002](../../adr/0002-bounded-provider-transport.md) records revisions, scope,
accepted differences and limits, and [ORACLE.md](../../ORACLE.md) lists the other
retained receipts.

- Run `nix develop -c scripts/check` for the retained transport and pool tests.
- `test/warden/transport_test.gleam` and `test/warden/transport_pool_test.gleam` own the executable adapter contract.
