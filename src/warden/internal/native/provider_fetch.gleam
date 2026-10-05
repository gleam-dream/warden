//// One cache-owned provider fetch. This module has no shared coordinator;
//// its guardian exists only while one network operation is active.

import exception
import gleam/erlang/process.{type Subject}
import warden/internal/protocol.{type Failure}

pub type Background {
  Background(pid: process.Pid, monitor: process.Monitor)
}

type BackgroundEvent(a) {
  Fetched(Result(a, Failure))
  OwnerExited
  WorkerExited
}

/// A guardian remains responsive while HTTP or a telemetry observer blocks
/// the worker. It monitors the cache and links the worker, so either owner
/// loss or guardian failure terminates the work. The cache only monitors the
/// guardian: a worker failure cannot crash the cache or lose its snapshot.
pub fn start(
  self: Subject(message),
  fetch: fn() -> Result(a, Failure),
  deliver: fn(process.Pid, Result(a, Failure)) -> message,
) -> Background {
  let owner = process.self()
  let pid =
    process.spawn_unlinked(fn() {
      let owner_monitor = process.monitor(owner)
      let replies = process.new_subject()
      let worker =
        process.spawn(fn() {
          let result = case exception.rescue(fetch) {
            Ok(result) -> result
            Error(_) -> Error(protocol.Unmapped)
          }
          process.send(replies, Fetched(result))
        })
      // The monitor also observes normal exits without a result; links alone
      // ignore them. Messages from the worker precede its DOWN notification.
      let worker_monitor = process.monitor(worker)
      let event =
        process.new_selector()
        |> process.select(replies)
        |> process.select_specific_monitor(owner_monitor, fn(_) { OwnerExited })
        |> process.select_specific_monitor(worker_monitor, fn(_) {
          WorkerExited
        })
        |> process.selector_receive_forever
      case event {
        Fetched(result) -> process.send(self, deliver(process.self(), result))
        OwnerExited -> process.kill(worker)
        WorkerExited -> Nil
      }
    })
  Background(pid, process.monitor(pid))
}
