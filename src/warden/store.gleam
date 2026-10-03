//// A storage port for Warden's sessions (custody) and pending logins.
////
//// By default Warden keeps both in memory, under its own supervisor: a
//// restart signs every user out, and two nodes cannot share sessions. A
//// durable store removes both limits. It is one table of opaque records,
//// with three operations:
////
//// - `get(key)` returns the record or `None`;
//// - `put(record, expected)` writes atomically: with `None` only when no
////   record has the key, with `Some(version)` only when the stored record
////   has exactly that version. It returns `Ok(True)` when it wrote and
////   `Ok(False)` when the condition did not hold (nothing written);
//// - `delete_expired(now)` deletes records whose `expires_at` is not after
////   `now` and returns how many it deleted.
////
//// Warden keeps the whole protocol (login consumption, refresh reservation,
//// settlement, publication, logout tombstones) and needs only this
//// compare-and-set. In PostgreSQL it is one table:
////
//// ```sql
//// create table warden_records (
////   key text primary key,
////   version bigint not null,
////   expires_at timestamptz not null,
////   sealed bytea not null
//// );
//// -- put(record, None):        insert ... on conflict (key) do nothing
//// -- put(record, Some(v)):     update ... where key = $1 and version = v
//// -- delete_expired(now):      delete ... where expires_at <= $1
//// ```
////
//// ```gleam
//// let records =
////   store.new(
////     get: fn(key) { db.get(pool, key) },
////     put: fn(record, expected) { db.put(pool, record, expected) },
////     delete_expired: fn(now) { db.delete_expired(pool, now) },
////   )
//// config.new(issuer:, client_id:, redirect_uri:, authentication:)
//// |> config.with_custody_store(records)
//// |> config.with_sealing_key(sealing_key)
//// ```
////
//// Every record is sealed (AES-256-GCM) with the configured sealing key and
//// bound to its key and version, so a database reader learns no token,
//// verifier or session reference, and a database writer cannot forge or
//// move a session. Keys are digests: a session reference never reaches the
//// store. One table may hold both custody and login records; their keys do
//// not collide. `warden/testing.check_store` checks an adapter against this
//// contract.
////
//// Warden bounds every call with the configured store timeout and runs it
//// in a separate process, so a slow store fails one request instead of
//// hanging it.

import gleam/option.{type Option}
import gleam/time/timestamp.{type Timestamp}

/// One stored record. `sealed` is opaque to the store.
pub type Record {
  Record(key: String, version: Int, expires_at: Timestamp, sealed: BitArray)
}

pub type StoreError {
  /// The store did not act: nothing was read or written.
  StoreUnavailable
  /// The store may or may not have written (a timeout or a lost reply).
  StoreOutcomeUnknown
  /// The store refuses new records because it is at capacity. Nothing was
  /// written.
  StoreFull
}

/// A record store. Build one with `new`.
pub opaque type Store {
  Store(
    get: fn(String) -> Result(Option(Record), StoreError),
    put: fn(Record, Option(Int)) -> Result(Bool, StoreError),
    delete_expired: fn(Timestamp) -> Result(Int, StoreError),
  )
}

/// A store from its three operations (see the module documentation).
pub fn new(
  get get: fn(String) -> Result(Option(Record), StoreError),
  put put: fn(Record, Option(Int)) -> Result(Bool, StoreError),
  delete_expired delete_expired: fn(Timestamp) -> Result(Int, StoreError),
) -> Store {
  Store(get:, put:, delete_expired:)
}

/// Read the record with this key.
pub fn get(store: Store, key: String) -> Result(Option(Record), StoreError) {
  store.get(key)
}

/// Write a record: insert when `expected` is `None`, replace the record at
/// version `expected` otherwise. `Ok(False)` means the condition did not
/// hold and nothing was written.
pub fn put(
  store: Store,
  record: Record,
  expected: Option(Int),
) -> Result(Bool, StoreError) {
  store.put(record, expected)
}

/// Delete the records that expired at or before `now`.
pub fn delete_expired(store: Store, now: Timestamp) -> Result(Int, StoreError) {
  store.delete_expired(now)
}

/// Describe a store error for logs.
pub fn describe_error(error: StoreError) -> String {
  case error {
    StoreUnavailable -> "the store did not act"
    StoreOutcomeUnknown -> "the store may or may not have written"
    StoreFull -> "the store is at capacity"
  }
}
