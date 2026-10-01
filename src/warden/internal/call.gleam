//// Request/reply with an owned process that never panics.
////
//// `gleam/erlang/process.call` panics when the callee dies or the timeout
//// passes. Warden's stores are reached from request handlers, where a store
//// crash or slow reply must become a typed, recoverable outcome instead.
////
//// Each call runs through a short-lived proxy process that owns the reply
//// subject and enforces the timeout. A reply that arrives after the timeout
//// goes to the exited proxy and is dropped by the runtime, so it never
//// lands in the caller's mailbox, where it would hold login or token
//// material (internal security review, finding F4).

import gleam/erlang/process.{type Subject}

pub type CallError {
  /// No reply within the timeout. The callee may still have processed the
  /// request: the outcome is unknown.
  CallTimedOut
  /// The callee was not running or exited before replying. Whether it
  /// processed the request before exiting is unknown.
  CalleeDown
}

/// Margin for the proxy itself to be scheduled and report, beyond the
/// callee's timeout.
const proxy_margin_ms = 1000

pub fn call(
  subject: Subject(message),
  timeout: Int,
  make: fn(Subject(reply)) -> message,
) -> Result(reply, CallError) {
  let outcome = process.new_subject()
  let proxy =
    process.spawn_unlinked(fn() {
      process.send(outcome, direct(subject, timeout, make))
    })
  let monitor = process.monitor(proxy)
  let selector =
    process.new_selector()
    |> process.select(outcome)
    // The proxy sends its outcome before exiting, so a DOWN seen first
    // means it crashed.
    |> process.select_specific_monitor(monitor, fn(_) { Error(CalleeDown) })
  let result = case
    process.selector_receive(selector, timeout + proxy_margin_ms)
  {
    Ok(result) -> result
    Error(Nil) -> {
      process.kill(proxy)
      Error(CallTimedOut)
    }
  }
  process.demonitor_process(monitor)
  result
}

/// The request/reply itself, run inside the proxy.
fn direct(
  subject: Subject(message),
  timeout: Int,
  make: fn(Subject(reply)) -> message,
) -> Result(reply, CallError) {
  case process.subject_owner(subject) {
    Error(Nil) -> Error(CalleeDown)
    Ok(owner) -> {
      let monitor = process.monitor(owner)
      let reply_subject = process.new_subject()
      process.send(subject, make(reply_subject))
      let selector =
        process.new_selector()
        |> process.select_map(reply_subject, Ok)
        |> process.select_specific_monitor(monitor, fn(_) { Error(CalleeDown) })
      case process.selector_receive(selector, timeout) {
        Ok(outcome) -> outcome
        Error(Nil) -> Error(CallTimedOut)
      }
    }
  }
}
