//// Request/reply with an owned process that never panics.
////
//// `gleam/erlang/process.call` panics when the callee dies or the timeout
//// passes. Warden's stores are reached from request handlers, where a store
//// crash or slow reply must become a typed, recoverable outcome instead.

import gleam/erlang/process.{type Subject}

pub type CallError {
  /// No reply within the timeout. The callee may still have processed the
  /// request: the outcome is unknown.
  CallTimedOut
  /// The callee was not running or exited before replying. Whether it
  /// processed the request before exiting is unknown.
  CalleeDown
}

pub fn call(
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
      let result = case process.selector_receive(selector, timeout) {
        Ok(outcome) -> outcome
        Error(Nil) -> Error(CallTimedOut)
      }
      process.demonitor_process(monitor)
      result
    }
  }
}
