//// Pending-login store bounds under unauthenticated load (internal security
//// review, finding F1): expired logins free capacity, terminal records do
//// not count against it, and a full store answers without a full scan.

import gleam/erlang/process
import gleam/int
import gleam/option.{None}
import warden/internal/transaction_store as store
import warden/internal/transport
import warden_test_support as support

const lifetime = 10

/// Run `f` for each integer from `from` to `to`, inclusive.
fn each(from: Int, to: Int, f: fn(Int) -> Nil) -> Nil {
  int.range(from:, to: to + 1, with: Nil, run: fn(_, i) { f(i) })
}

fn material(expires_at: Int) -> store.Material {
  store.Material(
    state: "state",
    nonce: "nonce",
    verifier: "verifier",
    redirect_uri: "https://app.example/cb",
    browser_hash: "hash",
    max_age: None,
    created_at: expires_at - lifetime,
    expires_at:,
  )
}

fn start(capacity: Int, retention: Int) -> #(store.Store, support.Clock) {
  let clock = support.clock_new(1000)
  let name = process.new_name("transaction_store_test")
  let assert Ok(_) =
    store.start(
      clock: fn() { support.clock_read(clock) },
      capacity:,
      retention:,
      name:,
    )
  #(store.Store(process.named_subject(name), 5000), clock)
}

fn put(s: store.Store, key: String, clock: support.Clock) -> store.PutResult {
  let assert Ok(result) =
    store.put(s, key, material(support.clock_read(clock) + lifetime))
  result
}

pub fn expired_logins_free_capacity_test() {
  let #(s, clock) = start(2, 100)
  let assert store.Stored(_) = put(s, "a", clock)
  let assert store.Stored(_) = put(s, "b", clock)
  assert put(s, "c", clock) == store.CapacityExceeded
  // Both logins expire; their slots are free although retention is longer.
  support.clock_set(clock, 1000 + lifetime)
  let assert store.Stored(_) = put(s, "c", clock)
  let assert store.Stored(_) = put(s, "d", clock)
  // An expired login still reports expiry, not an unknown transaction.
  assert store.get(s, "a") == Ok(store.FoundExpired)
}

pub fn terminal_records_do_not_count_against_capacity_test() {
  let #(s, clock) = start(2, 100)
  let assert store.Stored(ra) = put(s, "a", clock)
  let assert store.Stored(rb) = put(s, "b", clock)
  let assert Ok(store.Consumed(_)) = store.consume(s, "a", ra)
  let assert Ok(store.Consumed(_)) = store.consume(s, "b", rb)
  let assert store.Stored(_) = put(s, "c", clock)
  let assert store.Stored(_) = put(s, "d", clock)
  // Replay is still reported for the consumed logins.
  assert store.consume(s, "a", ra) == Ok(store.AlreadyConsumed)
}

pub fn terminal_records_are_bounded_test() {
  let #(s, clock) = start(2, 100_000)
  each(1, 10, fn(i) {
    let key = "k" <> int.to_string(i)
    let assert store.Stored(r) = put(s, key, clock)
    let assert Ok(store.Consumed(_)) = store.consume(s, key, r)
    Nil
  })
  // Oldest terminal records are evicted first; recent ones remain.
  assert store.get(s, "k1") == Ok(store.NotFound)
  assert store.get(s, "k10") == Ok(store.FoundConsumed)
}

pub fn a_full_store_answers_without_scanning_test() {
  let capacity = 100_000
  let #(s, clock) = start(capacity, 600)
  each(1, capacity, fn(i) {
    let assert store.Stored(_) = put(s, int.to_string(i), clock)
    Nil
  })
  let started = transport.monotonic_ms()
  each(1, 50, fn(_) {
    assert put(s, "extra", clock) == store.CapacityExceeded
  })
  // Before the fix each rejected put swept every record (~18 ms each).
  assert transport.monotonic_ms() - started < 100
}
