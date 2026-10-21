# warden_postgres

A PostgreSQL adapter for Warden's public `warden/store` contract. It borrows a
caller-owned Pog pool, adds no application membership rules or FFI, and keeps
PostgreSQL out of Warden core. It is unpublished and not production qualified.

The adapter tests configure a separate schema on a caller-owned pool `name`:

<!-- prettier-ignore-start -->
<!-- snips: test/warden_postgres_test.gleam#configure-adapter -->
```gleam
let config = warden_postgres.config(name)
let assert Ok(isolated) =
  warden_postgres.new(
    config
    |> warden_postgres.with_schema("Other\"Warden")
    |> warden_postgres.with_timeouts(statement_ms: 2000, lock_ms: 250),
  )
let assert Ok(Nil) = warden_postgres.initialize(isolated)
let records = warden_postgres.records(isolated)
```
<!-- prettier-ignore-end -->

The login integration test supplies the resulting store to Warden. Its fixture
provides `db` and a local issuer `provider`; `key` is the sealing key prepared by
the test:

<!-- prettier-ignore-start -->
<!-- snips: test/warden_postgres_test.gleam#configure-client -->
```gleam
let records = warden_postgres.records(adapter(db))
let config =
  testing.config(provider, "https://app.test/callback")
  |> config.with_custody_store(records)
  |> config.with_transaction_store(records)
  |> config.with_sealing_key(key)
```
<!-- prettier-ignore-end -->

- `new` validates configuration without I/O. `initialize` serializes schema setup and rejects unknown formats.
- The application owns the pool, the sealing keys across restarts and rotation, and the synchronization of database and Warden host clocks.
- The adapter prunes nothing and retries nothing. An uncertain write returns `StoreOutcomeUnknown`.
- The design's "Optional PostgreSQL integration" section states the write, clock, timeout and format semantics.

Run the adapter's public consumer from the Warden repository root:

```sh
nix develop --command scripts/postgres-check
```

The script creates and removes its own temporary PostgreSQL cluster. Gleam fetches
HTTP Gun and Sinal from the Git dependencies in `gleam.toml`, at the commits locked in `manifest.toml`.
