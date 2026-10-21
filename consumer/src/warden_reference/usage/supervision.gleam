//// Usage: run a client under an application supervisor.
////
//// `warden.new` allocates stable names once, so the `client` handle stays
//// valid after process replacement. A supervised client discovers the
//// provider in the background; operations answer a provider-unavailable
//// failure until fresh compatible metadata and keys arrive. `run` starts
//// the tree against the local test provider and waits for readiness.

import gleam/erlang/process
import gleam/http/request
import gleam/otp/actor
import gleam/otp/static_supervisor as supervisor
import gleam/result
import gleam/time/duration
import warden
import warden/config
import warden/testing

// snips-start: supervision
pub fn under_supervision(
  configuration: config.Config,
) -> Result(#(warden.Client, actor.Started(supervisor.Supervisor)), String) {
  let assert Ok(client) = warden.new(configuration)
  supervisor.new(supervisor.OneForOne)
  |> supervisor.add(warden.supervised(client))
  |> supervisor.start
  |> result.map(fn(started) { #(client, started) })
  |> result.replace_error("the supervision tree did not start")
}

// snips-end: supervision

/// The Erlang exit reason `shutdown`.
type ExitReason {
  Shutdown
}

/// Starts the tree, waits until discovery has succeeded, signs a user in,
/// and stops the client through its parent.
pub fn run() -> Nil {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  let configuration =
    testing.config(provider, "https://app.test/callback")
    |> config.with_startup_timeout(duration.seconds(5))
  let assert Ok(#(client, started)) = under_supervision(configuration)
  // Background discovery: operations fail until the provider is ready.
  assert wait_until_ready(client, 100) == Ok(Nil)
  let assert Ok(redirect) =
    warden.begin_login(client, request.new(), warden.default_login())
  let assert Ok(callback) =
    testing.authorize(provider, redirect, subject: "ada")
  let assert Ok(session) = warden.complete_login(client, callback)
  assert warden.subject(warden.session_identity(session)) == "ada"
  // Stop a supervised client through its parent. `warden.stop` would be
  // undone by the supervisor's restart.
  process.unlink(started.pid)
  process.send_abnormal_exit(started.pid, Shutdown)
  testing.stop_provider(provider)
}

fn wait_until_ready(client: warden.Client, attempts: Int) -> Result(Nil, Nil) {
  case warden.begin_login(client, request.new(), warden.default_login()) {
    Ok(_) -> Ok(Nil)
    Error(warden.LoginProviderUnavailable(warden.ProviderNotReady)) ->
      case attempts {
        0 -> Error(Nil)
        _ -> {
          process.sleep(50)
          wait_until_ready(client, attempts - 1)
        }
      }
    Error(_) -> Error(Nil)
  }
}
