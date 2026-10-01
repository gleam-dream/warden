//// Operational behaviour (gate V6): provider worker loss and restart, key
//// rotation, bounded pending logins, atom and process growth.

import gleam/list
import gleam/option.{None, Some}
import gleam/string
import warden
import warden/config
import warden_login_test.{authorize, logged_in, param, settings, start}
import warden_test_support as support

pub fn provider_worker_crash_is_typed_and_recovers_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let worker = warden.provider_worker(client)
  support.worker_kill(worker)
  // While the worker restarts and rediscovers, operations fail typed or
  // succeed; they never crash the caller.
  let early = warden.begin_login(client, None, warden.default_login())
  case early {
    Ok(_) | Error(warden.LoginProviderUnavailable(_)) -> Nil
    Error(other) -> panic as string.inspect(other)
  }
  wait_until(fn() { support.worker_alive(worker) }, 100)
  wait_until(
    fn() {
      case warden.begin_login(client, None, warden.default_login()) {
        Ok(_) -> True
        Error(_) -> False
      }
    },
    100,
  )
  let _ = logged_in(provider, client)
  warden.stop(client)
  support.provider_stop(provider)
}

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

pub fn signing_key_rotation_refreshes_keys_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let _ = logged_in(provider, client)
  support.rotate_key(provider)
  // The next ID token carries an unknown kid; oidcc refreshes the JWKS
  // through Warden's transport and the login succeeds.
  let _ = logged_in(provider, client)
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn pending_logins_are_bounded_test() {
  let provider = support.provider_start(support.Standard)
  let client =
    start(config.Settings(..settings(provider), max_pending_logins: 5))
  let results =
    list.repeat(Nil, 8)
    |> list.map(fn(_) {
      warden.begin_login(client, None, warden.default_login())
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
    warden.begin_login(client, None, warden.default_login())
  let before = support.atom_count()
  list.repeat(Nil, 500)
  |> list.index_map(fn(_, i) {
    let n = string.inspect(i)
    let _ =
      warden.complete_login(
        client,
        warden.QueryCallback(
          "code=c"
          <> n
          <> "&state=s"
          <> n
          <> "&error_x"
          <> n
          <> "=1&iss=https://x"
          <> n,
        ),
        Some(redirect.browser_binding),
      )
    let _ =
      warden.complete_login(
        client,
        warden.QueryCallback(
          "error=weird_" <> n <> "&state=" <> param(redirect.url, "state"),
        ),
        Some(redirect.browser_binding),
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
    let assert Ok(warden.RefreshCompleted(_)) =
      warden.refresh_session(client, session)
    Nil
  })
  support.sleep(200)
  assert support.process_count() - before < 20
  let _ = authorize
  warden.stop(client)
  support.provider_stop(provider)
}
