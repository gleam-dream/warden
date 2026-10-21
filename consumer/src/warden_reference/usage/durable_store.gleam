//// Usage: durable sessions across restarts and several nodes.
////
//// By default sessions and pending logins live in memory, so a restart of
//// the custody store loses them (`SessionLost`). A store adapter is three
//// functions over the application's database; Warden seals every record
//// (AES-256-GCM) and binds it to its key and version, so the database holds
//// no token, verifier or session reference. The in-memory store from
//// `warden/testing` stands in for a database table here; each adapter
//// implements the same conditional-write contract.

import gleam/crypto
import gleam/http/request
import gleam/option.{Some}
import gleam/time/timestamp
import warden
import warden/config
import warden/store
import warden/testing

// snips-start: durable-store
/// An adapter is three functions. A database table replaces the stand-in.
pub fn adapter(table: store.Store) -> store.Store {
  store.new(
    get: fn(key) { store.get(table, key) },
    put: fn(record, condition) { store.put(table, record, condition) },
    delete_expired: fn(now) { store.delete_expired(table, now) },
  )
}

/// Durable custody and login storage, sealed with a 32-byte key from a
/// secret manager.
pub fn with_durable_store(
  configuration: config.Config,
  records: store.Store,
  sealing_key_bytes: BitArray,
) -> config.Config {
  let assert Ok(key) = config.sealing_key(sealing_key_bytes)
  configuration
  |> config.with_custody_store(records)
  |> config.with_transaction_store(records)
  |> config.with_sealing_key(key)
}

// snips-end: durable-store

/// The conditional write: `Absent` inserts, `AtVersion` replaces, and
/// `AtVersionBefore` replaces only before a validity deadline. A refusal
/// leaves the record unchanged, and a version conflict outranks expiry.
pub fn conditional_writes() -> Nil {
  let records = testing.memory_store()
  let past = timestamp.from_unix_seconds(1_000_000)
  let future = timestamp.from_unix_seconds(4_000_000_000)
  let record = fn(version, bytes) {
    store.Record(key: "usage", version:, expires_at: future, sealed: bytes)
  }
  assert store.put(records, record(1, <<1>>), store.Absent) == Ok(store.Written)
  assert store.put(records, record(1, <<2>>), store.Absent)
    == Ok(store.VersionConflict)
  assert store.put(records, record(2, <<3>>), store.AtVersion(1))
    == Ok(store.Written)
  assert store.put(records, record(3, <<4>>), store.AtVersion(1))
    == Ok(store.VersionConflict)
  // The version matches but the validity deadline has passed.
  assert store.put(records, record(3, <<5>>), store.AtVersionBefore(2, past))
    == Ok(store.DeadlineElapsed)
  // A stale version is a conflict even when the deadline has also passed.
  assert store.put(records, record(3, <<6>>), store.AtVersionBefore(1, past))
    == Ok(store.VersionConflict)
  assert store.get(records, "usage") == Ok(Some(record(2, <<3>>)))
  assert store.put(records, record(3, <<7>>), store.AtVersionBefore(2, future))
    == Ok(store.Written)
  Nil
}

/// A second client on the same store and sealing key (another node) restores
/// a session the first client created, and the adapter passes the contract
/// check.
pub fn run() -> Nil {
  conditional_writes()
  let table = testing.memory_store()
  let records = adapter(table)
  assert testing.check_store(records) == Ok(Nil)
  let key = crypto.strong_random_bytes(32)
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  let node = fn() {
    let assert Ok(client) =
      warden.new(
        testing.config(provider, "https://app.test/callback")
        |> with_durable_store(records, key),
      )
    let assert Ok(Nil) = warden.start(client)
    client
  }
  let first = node()
  let assert Ok(redirect) =
    warden.begin_login(first, request.new(), warden.default_login())
  let assert Ok(callback) =
    testing.authorize(provider, redirect, subject: "ada")
  let assert Ok(session) = warden.complete_login(first, callback)
  let second = node()
  let assert Ok(restored) =
    warden.restore_session(second, warden.session_reference(session))
  assert warden.subject(warden.session_identity(restored)) == "ada"
  warden.stop(second)
  warden.stop(first)
  testing.stop_provider(provider)
}
