//// Fault injection around a `warden/store.Store`: slow reads, lost write
//// acknowledgements (the write happens, the reply is lost), and a hook run
//// after each read. Faults are set through a small control actor.

import gleam/crypto
import gleam/erlang/process.{type Subject}
import gleam/option.{type Option, None, Some}
import gleam/otp/actor
import warden/config
import warden/store.{type Store}
import warden/testing

pub type Faults {
  Faults(
    /// Delay every `get` by this many milliseconds.
    get_delay_ms: Int,
    /// Lose the acknowledgement of the n-th `put` from now (1 = the next):
    /// the write is applied, then the call sleeps `ack_delay_ms` and reports
    /// `StoreOutcomeUnknown`.
    lose_ack_of: Option(Int),
    ack_delay_ms: Int,
    /// Run after each successful `get`.
    after_get: fn() -> Nil,
    puts: Int,
  )
}

pub type Control =
  Subject(Message)

pub opaque type Message {
  Read(reply: Subject(Faults))
  Change(fn(Faults) -> Faults)
  CountPut(reply: Subject(Bool))
}

pub fn faulty(inner: Store) -> #(Store, Control) {
  let assert Ok(started) =
    actor.new(Faults(
      get_delay_ms: 0,
      lose_ack_of: None,
      ack_delay_ms: 0,
      after_get: fn() { Nil },
      puts: 0,
    ))
    |> actor.on_message(fn(faults, message) {
      case message {
        Read(reply) -> {
          process.send(reply, faults)
          actor.continue(faults)
        }
        Change(change) -> actor.continue(change(faults))
        CountPut(reply) -> {
          let puts = faults.puts + 1
          let lose = faults.lose_ack_of == Some(puts)
          process.send(reply, lose)
          let faults = case lose {
            True -> Faults(..faults, lose_ack_of: None, puts: 0)
            False -> Faults(..faults, puts:)
          }
          actor.continue(faults)
        }
      }
    })
    |> actor.start
  let control = started.data
  let store =
    store.new(
      get: fn(key) {
        let faults = process.call(control, 1000, Read)
        process.sleep(faults.get_delay_ms)
        let found = store.get(inner, key)
        faults.after_get()
        found
      },
      put: fn(record, expected) {
        let lose = process.call(control, 1000, CountPut)
        let written = store.put(inner, record, expected)
        case lose {
          False -> written
          True -> {
            let faults = process.call(control, 1000, Read)
            process.sleep(faults.ack_delay_ms)
            Error(store.StoreOutcomeUnknown)
          }
        }
      },
      delete_expired: fn(now) { store.delete_expired(inner, now) },
    )
  #(store, control)
}

pub fn set(control: Control, change: fn(Faults) -> Faults) -> Nil {
  process.send(control, Change(change))
  // Make the change visible before the caller goes on.
  let _ = process.call(control, 1000, Read)
  Nil
}

/// Lose the acknowledgement of the n-th write from now.
pub fn lose_ack_of(control: Control, n: Int) -> Nil {
  set(control, fn(f) { Faults(..f, lose_ack_of: Some(n), puts: 0) })
}

pub fn sealing_key() -> config.SealingKey {
  let assert Ok(key) = config.sealing_key(crypto.strong_random_bytes(32))
  key
}

/// A faulty in-memory store for a configuration.
pub fn memory() -> #(Store, Control) {
  faulty(testing.memory_store())
}
