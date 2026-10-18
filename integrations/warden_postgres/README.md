# warden_postgres

A PostgreSQL adapter for Warden's public `warden/store` contract. It borrows a
caller-owned Pog pool, adds no application membership rules or FFI, and keeps
PostgreSQL out of Warden core. It is unpublished and not production qualified.

```gleam
let settings = warden_postgres.config(pool_name)
  |> warden_postgres.with_schema("authentication")
  |> warden_postgres.with_timeouts(statement_ms: 1000, lock_ms: 250)
let assert Ok(adapter) = warden_postgres.new(settings)
let assert Ok(Nil) = warden_postgres.initialize(adapter)
let records = warden_postgres.records(adapter)
let settings = oidc_config
  |> config.with_transaction_store(records)
  |> config.with_custody_store(records)
  |> config.with_sealing_key(key_from_secret_storage)
```

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
