//// Bounded calls into a `warden/store.Store`.
////
//// Each call runs in a short-lived process and is abandoned after the store
//// timeout, so a slow or crashing adapter fails one operation with a typed
//// error. A read that does not finish is `StoreUnavailable` (nothing
//// changed); a write that does not finish is `StoreOutcomeUnknown`.

import exception
import gleam/erlang/process
import gleam/option.{type Option}
import gleam/time/timestamp.{type Timestamp}
import warden/store.{
  type Record, type Store, type StoreError, StoreOutcomeUnknown,
  StoreUnavailable,
}

pub type Port {
  Port(store: Store, timeout_ms: Int)
}

pub fn get(port: Port, key: String) -> Result(Option(Record), StoreError) {
  bounded(port.timeout_ms, StoreUnavailable, fn() { store.get(port.store, key) })
}

pub fn put(
  port: Port,
  record: Record,
  expected: Option(Int),
) -> Result(Bool, StoreError) {
  bounded(port.timeout_ms, StoreOutcomeUnknown, fn() {
    store.put(port.store, record, expected)
  })
}

pub fn delete_expired(port: Port, now: Timestamp) -> Result(Int, StoreError) {
  bounded(port.timeout_ms, StoreOutcomeUnknown, fn() {
    store.delete_expired(port.store, now)
  })
}

/// The same port with a shorter bound, for operations under a deadline.
pub fn within(port: Port, remaining_ms: Int) -> Port {
  case remaining_ms < port.timeout_ms {
    True -> Port(..port, timeout_ms: int_max(1, remaining_ms))
    False -> port
  }
}

fn int_max(a: Int, b: Int) -> Int {
  case a > b {
    True -> a
    False -> b
  }
}

fn bounded(
  timeout_ms: Int,
  on_failure: StoreError,
  run: fn() -> Result(a, StoreError),
) -> Result(a, StoreError) {
  let reply = process.new_subject()
  let worker =
    process.spawn_unlinked(fn() {
      let outcome = case exception.rescue(run) {
        Ok(outcome) -> outcome
        Error(_) -> Error(on_failure)
      }
      process.send(reply, outcome)
    })
  let monitor = process.monitor(worker)
  let selector =
    process.new_selector()
    |> process.select(reply)
    |> process.select_specific_monitor(monitor, fn(_) { Error(on_failure) })
  case process.selector_receive(selector, timeout_ms) {
    Ok(outcome) -> {
      process.demonitor_process(monitor)
      outcome
    }
    Error(Nil) -> {
      process.kill(worker)
      // Signals from one process arrive in order, so once its DOWN is here a
      // reply it sent first is in the mailbox too: drop it.
      let _ =
        process.new_selector()
        |> process.select_specific_monitor(monitor, fn(_) { Nil })
        |> process.selector_receive(1000)
      let _ = process.receive(reply, 0)
      Error(on_failure)
    }
  }
}
