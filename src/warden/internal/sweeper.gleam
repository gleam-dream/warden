//// Deletes expired session and login records every minute, so abandoned
//// sessions and logins leave the stores with their tokens. Each sweep is
//// one bounded `delete_expired` call per store; a failure waits for the
//// next tick.

import gleam/erlang/process.{type Subject}
import gleam/list
import gleam/otp/actor
import gleam/time/timestamp
import warden/internal/port.{type Port}

pub const interval_ms = 60_000

pub opaque type Message {
  Tick
  SweepNow(reply: Subject(Nil))
}

type State {
  State(self: Subject(Message), ports: List(Port), clock: fn() -> Int)
}

pub fn start(
  name: process.Name(Message),
  ports: List(Port),
  clock: fn() -> Int,
) -> actor.StartResult(Subject(Message)) {
  actor.new_with_initialiser(1000, fn(self) {
    process.send_after(self, interval_ms, Tick)
    actor.initialised(State(self:, ports:, clock:))
    |> actor.returning(self)
    |> Ok
  })
  |> actor.named(name)
  |> actor.on_message(handle)
  |> actor.start
}

fn handle(state: State, message: Message) -> actor.Next(State, Message) {
  case message {
    Tick -> {
      sweep(state)
      process.send_after(state.self, interval_ms, Tick)
      actor.continue(state)
    }
    SweepNow(reply) -> {
      sweep(state)
      process.send(reply, Nil)
      actor.continue(state)
    }
  }
}

fn sweep(state: State) -> Nil {
  let now = timestamp.from_unix_seconds(state.clock())
  list.each(state.ports, fn(port) {
    let _ = port.delete_expired(port, now)
    Nil
  })
}

/// Sweep now and wait for it (tests).
pub fn sweep_now(subject: Subject(Message), timeout_ms: Int) -> Nil {
  let _ = process.call(subject, timeout_ms, SweepNow)
  Nil
}
