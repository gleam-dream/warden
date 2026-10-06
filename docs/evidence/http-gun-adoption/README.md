# HTTP transport receipts

- `logs/` contains the retained adoption experiment's raw outputs. Revisions,
  measured scope, accepted differences and limitations live in
  [ADR 0002](../../adr/0002-bounded-provider-transport.md).
- Run `nix develop -c scripts/check` for the retained transport/pool tests and
  consumer recipes. Run the relevant local provider suites from
  [TESTING.md](../../TESTING.md) when transport or resolved dependencies change.
- `src/warden/internal/transport.gleam`, `test/warden/transport_test.gleam` and
  `test/warden/transport_pool_test.gleam` own the executable adapter contract.
  Provider/body/effect limits belong to the native design.
- Raw pre-adoption failures are not a current rejection inventory. New claims
  need the relevant source, dependency and test revisions; the retained receipt
  does not qualify untested transport matrices or production load.
