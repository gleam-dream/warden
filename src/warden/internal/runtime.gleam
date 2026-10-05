//// The record behind `warden.Client`: validated configuration and the
//// names of the processes a started client runs. The names are allocated
//// once, by `warden.new`, so a client value stays valid across supervisor
//// restarts.

import gleam/erlang/process
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import sinal/correlation.{type Correlation}
import warden/internal/custody.{type Custody}
import warden/internal/logins.{type Logins}
import warden/internal/memory_store
import warden/internal/native/client as native
import warden/internal/native/provider
import warden/internal/secure
import warden/internal/settings.{type Settings}
import warden/internal/sweeper
import warden/internal/transport

pub type Names {
  Names(
    supervisor: process.Name(Nil),
    provider: process.Name(provider.Message),
    sweeper: process.Name(sweeper.Message),
    /// The in-memory stores, when no durable store is configured.
    memory_custody: Option(process.Name(memory_store.Message)),
    memory_logins: Option(process.Name(memory_store.Message)),
    pool: transport.Pool,
  )
}

pub type Client {
  Client(
    settings: Settings,
    /// `issuer client_id`: binds sessions and recoveries to this client.
    provider: String,
    names: Names,
    backend: native.Client,
    custody: Custody,
    logins: Logins,
    /// Request policy on the client's shared HTTP Gun client.
    http: transport.Policy,
    correlation: Option(Correlation),
  )
}

/// Join actual processes still registered by the previous client tree.
/// The caller first checks that the client supervisor is gone. A killed
/// supervisor may exit before all its linked children have released names.
/// All monitors are installed before waiting and share one startup deadline.
pub fn await_previous_children(
  names: Names,
  deadline: Int,
) -> Result(Nil, Nil) {
  let monitors =
    [
      transport.pool_process(names.pool),
      process.named(names.provider),
      process.named(names.sweeper),
      optional_process(names.memory_logins),
      optional_process(names.memory_custody),
    ]
    |> list.filter_map(fn(pid) { pid })
    |> list.map(process.monitor)
  let outcome = await_exits(monitors, deadline)
  list.each(monitors, process.demonitor_process)
  outcome
}

fn optional_process(name: Option(process.Name(a))) -> Result(process.Pid, Nil) {
  case name {
    Some(name) -> process.named(name)
    None -> Error(Nil)
  }
}

fn await_exits(
  monitors: List(process.Monitor),
  deadline: Int,
) -> Result(Nil, Nil) {
  case monitors {
    [] -> Ok(Nil)
    [monitor, ..rest] -> {
      let remaining = deadline - secure.monotonic_ms()
      case remaining <= 0 {
        True -> Error(Nil)
        False -> {
          use _ <- result.try(
            process.new_selector()
            |> process.select_specific_monitor(monitor, fn(_) { Nil })
            |> process.selector_receive(remaining),
          )
          await_exits(rest, deadline)
        }
      }
    }
  }
}
