//// Operational behaviour: lifecycle and supervision, provider
//// worker loss and restart, key rotation, bounded pending logins, atom and
//// process growth.

import exception
import gleam/erlang/atom
import gleam/erlang/process
import gleam/http/request
import gleam/http/response
import gleam/list
import gleam/option.{None, Some}
import gleam/otp/actor
import gleam/otp/static_supervisor as supervisor
import gleam/string
import gleam/time/duration
import warden
import warden/config
import warden/testing
import warden_login_test.{authorize, browser, logged_in, param, settings, start}
import warden_test_support as support

fn wait_until(check: fn() -> Bool, tries: Int) -> Nil {
  case check() {
    True -> Nil
    False if tries <= 0 -> panic as "condition not reached"
    False -> {
      support.sleep(50)
      wait_until(check, tries - 1)
    }
  }
}

fn can_begin(client: warden.Client) -> Bool {
  case warden.begin_login(client, browser(), warden.default_login()) {
    Ok(_) -> True
    Error(_) -> False
  }
}

fn with_supervised(client: warden.Client, run: fn() -> a) -> a {
  let assert Ok(actor.Started(pid: parent, ..)) =
    supervisor.new(supervisor.OneForOne)
    |> supervisor.add(warden.supervised(client))
    |> supervisor.start
  use <- exception.defer(fn() {
    let monitor = process.monitor(parent)
    process.unlink(parent)
    process.send_abnormal_exit(parent, atom.create("shutdown"))
    let assert Ok(_) =
      process.new_selector()
      |> process.select_specific_monitor(monitor, fn(down) { down })
      |> process.selector_receive(5000)
  })
  run()
}

pub fn provider_worker_crash_is_typed_and_recovers_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let worker = client.names.provider
  support.worker_kill(worker)
  // While the worker restarts and rediscovers, operations fail typed or
  // succeed; they never crash the caller.
  case warden.begin_login(client, browser(), warden.default_login()) {
    Ok(_) | Error(warden.LoginProviderUnavailable(_)) -> Nil
    Error(other) -> panic as string.inspect(other)
  }
  wait_until(fn() { support.worker_alive(worker) }, 100)
  wait_until(fn() { can_begin(client) }, 100)
  let _ = logged_in(provider, client)
  warden.stop(client)
  support.provider_stop(provider)
}

/// Under a supervisor, the child starts without waiting for the
/// provider; operations answer `ProviderNotReady` until background
/// discovery succeeds.
pub fn supervised_client_discovers_in_the_background_test() {
  // A provider that is not there yet: nothing listens on this issuer.
  let unreachable =
    config.new(
      issuer: "https://localhost:1",
      client_id: "warden-rp",
      redirect_uri: "https://app.example/callback",
      authentication: config.ClientSecretBasic(config.secret("sentinel-secret")),
    )
    |> config.with_destinations(config.AllowLoopbackForTesting)
  let assert Ok(client) = warden.new(unreachable)
  with_supervised(client, fn() {
    assert warden.begin_login(client, browser(), warden.default_login())
      == Error(warden.LoginProviderUnavailable(warden.ProviderNotReady))
  })
  // A reachable provider: ready shortly after the child started.
  let provider = support.provider_start(support.Standard)
  let assert Ok(client) = warden.new(settings(provider))
  with_supervised(client, fn() {
    wait_until(fn() { can_begin(client) }, 100)
    let _ = logged_in(provider, client)
    Nil
  })
  support.provider_stop(provider)
}

/// The client value names its processes, so it stays valid when its
/// supervisor restarts the whole Warden tree.
pub fn the_client_survives_a_restart_of_its_tree_test() {
  let provider = support.provider_start(support.Standard)
  let assert Ok(client) = warden.new(settings(provider))
  use <- exception.defer(fn() { support.provider_stop(provider) })
  use <- with_supervised(client)
  wait_until(fn() { can_begin(client) }, 100)
  let assert Ok(first) = process.named(client.names.supervisor)
  process.kill(first)
  wait_until(
    fn() {
      case process.named(client.names.supervisor) {
        Ok(pid) -> pid != first
        Error(Nil) -> False
      }
    },
    100,
  )
  wait_until(fn() { can_begin(client) }, 100)
  let _ = logged_in(provider, client)
  Nil
}

pub fn a_started_client_cannot_start_twice_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  assert warden.start(client) == Error(warden.AlreadyStarted)
  warden.stop(client)
  // Stopped, it can start again with the same value.
  let assert Ok(Nil) = warden.start(client)
  let _ = logged_in(provider, client)
  warden.stop(client)
  support.provider_stop(provider)
}

/// A service client needs no redirect URI and no authorization-code
/// support; login is not configured.
pub fn service_client_starts_without_login_test() {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  let assert Ok(client) = warden.new(testing.service_config(provider))
  let assert Ok(Nil) = warden.start(client)
  assert warden.begin_login(client, browser(), warden.default_login())
    == Error(warden.LoginNotConfigured)
  assert warden.complete_login(client, browser())
    == Error(warden.LoginNotConfigured)
  let assert Ok(_) = warden.client_credentials(client, [])
  warden.stop(client)
  testing.stop_provider(provider)
}

pub fn signing_key_rotation_refreshes_keys_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let _ = logged_in(provider, client)
  support.rotate_key(provider)
  // The next ID token carries an unknown kid; Warden refreshes the JWKS
  // and the login succeeds.
  let _ = logged_in(provider, client)
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn pending_logins_are_bounded_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider) |> config.with_max_pending_logins(5))
  let results =
    list.repeat(Nil, 8)
    |> list.map(fn(_) {
      warden.begin_login(client, browser(), warden.default_login())
    })
  assert list.count(results, fn(r) { r == Error(warden.TooManyPendingLogins) })
    == 3
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn hostile_callbacks_create_no_atoms_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let assert Ok(redirect) =
    warden.begin_login(client, browser(), warden.default_login())
  let state = param(warden.login_url(redirect), "state")
  let before = support.atom_count()
  list.repeat(Nil, 500)
  |> list.index_map(fn(_, i) {
    let n = string.inspect(i)
    let _ =
      warden.complete_login(
        client,
        request.Request(
          ..testing.browser_request(redirect),
          query: Some(
            "code=c"
            <> n
            <> "&state=s"
            <> n
            <> "&error_x"
            <> n
            <> "=1&iss=https://x"
            <> n,
          ),
        ),
      )
    let _ =
      warden.complete_login(
        client,
        request.Request(
          ..testing.browser_request(redirect),
          query: Some("error=weird_" <> n <> "&state=" <> state),
        ),
      )
    Nil
  })
  assert support.atom_count() - before < 10
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn repeated_logins_do_not_leak_processes_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let _ = logged_in(provider, client)
  let before = support.process_count()
  list.repeat(Nil, 100)
  |> list.each(fn(_) {
    let session = logged_in(provider, client)
    let assert Ok(_) = warden.refresh(client, session)
    Nil
  })
  support.sleep(200)
  assert support.process_count() - before < 20
  let _ = authorize
  warden.stop(client)
  support.provider_stop(provider)
}

/// The login response is a 303 with the binding cookie Warden owns:
/// `__Host-`, `Secure`, `HttpOnly`, `Path=/`, `SameSite` by response mode,
/// and no caching.
pub fn login_response_sets_the_binding_cookie_safely_test() {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  let cookie_of = fn(mode) {
    let assert Ok(client) =
      warden.new(
        testing.config(provider, "https://app.test/callback")
        |> config.with_response_mode(mode),
      )
    let assert Ok(Nil) = warden.start(client)
    let assert Ok(redirect) =
      warden.begin_login(client, browser(), warden.default_login())
    let reply = warden.login_response(response.new(200), redirect)
    warden.stop(client)
    assert reply.status == 303
    assert response.get_header(reply, "location")
      == Ok(warden.login_url(redirect))
    assert response.get_header(reply, "cache-control") == Ok("no-store")
    let assert Ok(cookie) = response.get_header(reply, "set-cookie")
    cookie
  }
  let query = cookie_of(config.Query)
  assert string.starts_with(query, "__Host-warden_binding=")
  list.each(
    ["Secure", "HttpOnly", "Path=/", "SameSite=Lax", "Max-Age=900"],
    fn(attribute) {
      assert #(attribute, string.contains(query, attribute))
        == #(attribute, True)
    },
  )
  assert !string.contains(query, "Domain")
  let form = cookie_of(config.FormPost)
  assert string.contains(form, "SameSite=None")
  assert string.contains(form, "Secure")
  testing.stop_provider(provider)
}

/// The provider-cache call waits as long as a key fetch can take.
pub fn provider_calls_wait_for_one_request_timeout_test() {
  let assert Ok(client) =
    warden.new(
      config.new(
        issuer: "https://idp.example",
        client_id: "app",
        redirect_uri: "https://app.example/cb",
        authentication: config.PublicClient,
      )
      |> config.with_request_timeout(duration.seconds(12)),
    )
  assert client.backend.provider.timeout == 13_000
  let _ = None
}
