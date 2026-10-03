//// The record store port: the in-memory store meets the contract, a
//// broken adapter is caught by `testing.check_store`, the login store is
//// bounded, and a slow store fails one call without leaking its reply.

import gleam/erlang/process
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleam/time/timestamp
import warden/internal/memory_store
import warden/internal/port
import warden/internal/secure
import warden/store
import warden/testing
import warden_test_support as support

pub fn the_memory_store_meets_the_contract_test() {
  assert testing.check_store(testing.memory_store()) == Ok(Nil)
}

/// An adapter without compare-and-set fails the conformance check.
pub fn a_store_without_compare_and_set_fails_the_check_test() {
  let inner = testing.memory_store()
  let careless =
    store.new(
      get: fn(key) { store.get(inner, key) },
      // Ignores the condition: last write wins.
      put: fn(record, _expected) {
        let current = store.get(inner, record.key)
        let expected = case current {
          Ok(Some(existing)) -> Some(existing.version)
          _ -> None
        }
        store.put(inner, record, expected)
      },
      delete_expired: fn(now) { store.delete_expired(inner, now) },
    )
  let assert Error(failures) = testing.check_store(careless)
  assert list.contains(failures, "insert of a present key is refused")
  assert list.contains(failures, "replace at a stale version is refused")
  assert list.all(failures, fn(f) { !string.is_empty(f) })
}

fn record(key: String, expires: Int) -> store.Record {
  store.Record(
    key:,
    version: 1,
    expires_at: timestamp.from_unix_seconds(expires),
    sealed: <<1>>,
  )
}

/// The built-in login store's capacity: expired records free room, a full
/// store refuses inserts without a scan, and replaces are never refused.
pub fn the_memory_store_is_bounded_test() {
  let clock = support.clock_new(1000)
  let name = process.new_name("bounded_store_test")
  let assert Ok(_) =
    memory_store.start(name, Some(2), fn() { support.clock_read(clock) })
  let bounded = memory_store.store(process.named_subject(name), 5000)
  assert store.put(bounded, record("a", 1010), None) == Ok(True)
  assert store.put(bounded, record("b", 1010), None) == Ok(True)
  assert store.put(bounded, record("c", 1010), None) == Error(store.StoreFull)
  // A replace of a present record is not an insert.
  assert store.put(
      bounded,
      store.Record(..record("a", 1010), version: 2),
      Some(1),
    )
    == Ok(True)
  support.clock_set(clock, 1010)
  assert store.put(bounded, record("c", 2000), None) == Ok(True)
  assert store.put(bounded, record("d", 2000), None) == Ok(True)
}

pub fn a_full_store_answers_without_scanning_test() {
  let capacity = 100_000
  let name = process.new_name("full_store_test")
  let assert Ok(_) = memory_store.start(name, Some(capacity), fn() { 0 })
  let full = memory_store.store(process.named_subject(name), 5000)
  int.range(from: 0, to: capacity, with: Nil, run: fn(_, i) {
    let assert Ok(True) = store.put(full, record(int.to_string(i), 100), None)
    Nil
  })
  let started = secure.monotonic_ms()
  list.each(list.repeat(Nil, 50), fn(_) {
    assert store.put(full, record("extra", 100), None) == Error(store.StoreFull)
  })
  assert secure.monotonic_ms() - started < 200
}

/// A store call that outlives the store timeout fails typed, and its late
/// reply never reaches the caller's mailbox (finding F4).
pub fn slow_store_calls_fail_typed_without_late_replies_test() {
  let slow =
    store.new(
      get: fn(_) {
        process.sleep(200)
        Ok(None)
      },
      put: fn(_, _) {
        process.sleep(200)
        Ok(True)
      },
      delete_expired: fn(_) { Ok(0) },
    )
  let impatient = port.Port(store: slow, timeout_ms: 50)
  let before = support.mailbox_size()
  assert port.get(impatient, "k") == Error(store.StoreUnavailable)
  assert port.put(impatient, record("k", 1), None)
    == Error(store.StoreOutcomeUnknown)
  process.sleep(300)
  assert support.mailbox_size() == before
}

/// An adapter that raises fails typed instead of crashing the caller.
pub fn a_crashing_adapter_fails_typed_test() {
  let crashing =
    store.new(
      get: fn(_) { panic as "adapter bug" },
      put: fn(_, _) { panic as "adapter bug" },
      delete_expired: fn(_) { Ok(0) },
    )
  let p = port.Port(store: crashing, timeout_ms: 1000)
  assert port.get(p, "k") == Error(store.StoreUnavailable)
  assert port.put(p, record("k", 1), None) == Error(store.StoreOutcomeUnknown)
}
