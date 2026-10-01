//// Built-in login transaction store.
////
//// One actor owns every pending login. Its mailbox is the critical section:
//// `consume` loads the record, compares revision and status, samples the
//// store clock and commits the terminal state within a single message, so
//// concurrent callbacks for one transaction observe exactly one `Consumed`.
//// The clock is sampled only inside the actor, after the message is taken,
//// never from the caller.
////
//// Terminal records (consumed, expired) are kept for the retention window so
//// a losing or late callback reports replay or expiry rather than an unknown
//// transaction; they are removed afterwards to bound memory.

import gleam/dict.{type Dict}
import gleam/erlang/process.{type Subject}
import gleam/option.{type Option}
import gleam/otp/actor
import warden/internal/call.{type CallError}

/// Immutable material for one login. Secret-bearing; it never leaves Warden.
pub type Material {
  Material(
    state: String,
    nonce: String,
    verifier: String,
    redirect_uri: String,
    browser_hash: String,
    max_age: Option(Int),
    created_at: Int,
    expires_at: Int,
  )
}

type Record {
  Pending(material: Material, revision: Int)
  ConsumedRecord(revision: Int, at: Int)
  ExpiredRecord(revision: Int, at: Int)
}

pub type Lookup {
  Found(material: Material, revision: Int)
  FoundConsumed
  FoundExpired
  NotFound
}

pub type Decision {
  Consumed(Material)
  AlreadyConsumed
  Expired
  Changed
  Missing
}

pub type PutResult {
  Stored(revision: Int)
  CapacityExceeded
}

pub opaque type Message {
  Put(key: String, material: Material, reply: Subject(PutResult))
  Get(key: String, reply: Subject(Lookup))
  Consume(key: String, revision: Int, reply: Subject(Decision))
  Hold(reply: Subject(Subject(Nil)))
}

type State {
  State(
    records: Dict(String, Record),
    clock: fn() -> Int,
    capacity: Int,
    retention: Int,
    next_revision: Int,
  )
}

pub type Store {
  Store(subject: Subject(Message), timeout: Int)
}

pub fn start(
  clock clock: fn() -> Int,
  capacity capacity: Int,
  retention retention: Int,
  name name: process.Name(Message),
) -> actor.StartResult(Subject(Message)) {
  actor.new(State(
    records: dict.new(),
    clock:,
    capacity:,
    retention:,
    next_revision: 1,
  ))
  |> actor.named(name)
  |> actor.on_message(handle)
  |> actor.start
}

fn handle(state: State, message: Message) -> actor.Next(State, Message) {
  case message {
    Put(key, material, reply) -> {
      let state = case dict.size(state.records) >= state.capacity {
        True -> sweep(state)
        False -> state
      }
      case dict.size(state.records) >= state.capacity {
        True -> {
          process.send(reply, CapacityExceeded)
          actor.continue(state)
        }
        False -> {
          let revision = state.next_revision
          let records =
            dict.insert(state.records, key, Pending(material:, revision:))
          process.send(reply, Stored(revision))
          actor.continue(State(..state, records:, next_revision: revision + 1))
        }
      }
    }
    Get(key, reply) -> {
      let lookup = case dict.get(state.records, key) {
        Ok(Pending(material:, revision:)) -> Found(material:, revision:)
        Ok(ConsumedRecord(..)) -> FoundConsumed
        Ok(ExpiredRecord(..)) -> FoundExpired
        Error(Nil) -> NotFound
      }
      process.send(reply, lookup)
      actor.continue(state)
    }
    Consume(key, revision, reply) -> {
      let #(decision, records) = decide(state, key, revision)
      process.send(reply, decision)
      actor.continue(State(..state, records:))
    }
    Hold(reply) -> {
      let release = process.new_subject()
      process.send(reply, release)
      process.receive_forever(release)
      actor.continue(state)
    }
  }
}

/// The consumption transition. A terminal record takes precedence over the
/// revision comparison; a pending revision mismatch rejects before expiry or
/// mutation; the clock is sampled here, inside the critical section.
fn decide(
  state: State,
  key: String,
  revision: Int,
) -> #(Decision, Dict(String, Record)) {
  case dict.get(state.records, key) {
    Error(Nil) -> #(Missing, state.records)
    Ok(ConsumedRecord(..)) -> #(AlreadyConsumed, state.records)
    Ok(ExpiredRecord(..)) -> #(Expired, state.records)
    Ok(Pending(revision: current, ..)) if current != revision -> #(
      Changed,
      state.records,
    )
    Ok(Pending(material:, revision: current)) -> {
      let now = state.clock()
      case now < material.expires_at {
        True -> #(
          Consumed(material),
          dict.insert(state.records, key, ConsumedRecord(current, now)),
        )
        False -> #(
          Expired,
          dict.insert(state.records, key, ExpiredRecord(current, now)),
        )
      }
    }
  }
}

/// Remove terminal records past retention and convert expired pending
/// records into (retained) expired tombstones.
fn sweep(state: State) -> State {
  let now = state.clock()
  let records =
    dict.fold(state.records, dict.new(), fn(acc, key, record) {
      case record {
        Pending(material:, revision:) if now >= material.expires_at ->
          dict.insert(acc, key, ExpiredRecord(revision, now))
        Pending(..) -> dict.insert(acc, key, record)
        ConsumedRecord(at:, ..) | ExpiredRecord(at:, ..) ->
          case now - at > state.retention {
            True -> acc
            False -> dict.insert(acc, key, record)
          }
      }
    })
  State(..state, records:)
}

// ---------------------------------------------------------------------------
// Client functions

pub fn put(
  store: Store,
  key: String,
  material: Material,
) -> Result(PutResult, CallError) {
  call.call(store.subject, store.timeout, Put(key, material, _))
}

pub fn get(store: Store, key: String) -> Result(Lookup, CallError) {
  call.call(store.subject, store.timeout, Get(key, _))
}

pub fn consume(
  store: Store,
  key: String,
  revision: Int,
) -> Result(Decision, CallError) {
  call.call(store.subject, store.timeout, Consume(key, revision, _))
}

/// Test support: block the store inside its critical section. Returns the
/// subject that releases it; messages sent meanwhile queue behind the hold.
@internal
pub fn hold(store: Store) -> Result(Subject(Nil), CallError) {
  call.call(store.subject, store.timeout, Hold)
}
