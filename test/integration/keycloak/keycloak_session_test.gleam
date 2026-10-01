//// Session operations against the pinned Keycloak through Warden's API.

import gleam/dynamic/decode
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleam/uri
import warden
import warden/config
import warden_test_support as support

const issuer = "https://localhost:18443/realms/warden"

fn start() -> warden.Client {
  let assert Ok(validated) =
    config.new(
      issuer:,
      client_id: "warden-rp",
      redirect_uri: "https://localhost:1/callback",
      authentication: config.ClientSecretBasic(config.secret(
        "warden-rp-disposable-secret",
      )),
    )
    |> config.with_scopes(["profile", "email"])
    |> config.with_trust(config.TrustAnchorsPem(support.ca_pem()))
    |> config.with_destinations(config.AllowLoopbackForTesting)
    |> support.with_test_backend
    |> config.validate
  let assert Ok(client) = warden.start(validated)
  client
}

fn session(client: warden.Client) -> warden.Session {
  let assert Ok(redirect) =
    warden.begin_login(client, None, warden.default_login())
  let assert Ok(support.Query(query)) =
    support.keycloak_login(redirect.url, "alice", "alice-disposable")
  let assert Ok(warden.LoginCompleted(session)) =
    warden.complete_login(
      client,
      warden.QueryCallback(query),
      Some(redirect.browser_binding),
    )
  session
}

pub fn refresh_rotates_and_keeps_identity_test() {
  let client = start()
  let s0 = session(client)
  let assert Ok(warden.RefreshCompleted(s1)) =
    warden.refresh_session(client, s0)
  assert warden.session_revision(s1) == 2
  assert warden.identity_key(warden.session_identity(s1))
    == warden.identity_key(warden.session_identity(s0))
  let assert Ok(warden.RefreshCompleted(s2)) =
    warden.refresh_session(client, s1)
  assert warden.session_revision(s2) == 3
  // The stale session cannot dispatch the rotated-out refresh token.
  let assert Error(warden.RefreshSessionStale) =
    warden.refresh_session(client, s0)
  let assert Ok(info) = warden.userinfo(client, s2)
  assert warden.userinfo_subject(info)
    == warden.subject(warden.session_identity(s2))
  warden.stop(client)
}

pub fn concurrent_refresh_dispatches_once_test() {
  let client = start()
  let s0 = session(client)
  support.count_reset()
  let results =
    support.spawn_collect(
      list.repeat(fn() { warden.refresh_session(client, s0) }, 6),
      30_000,
    )
  let completed =
    list.count(results, fn(r) {
      case r {
        Ok(warden.RefreshCompleted(_)) -> True
        _ -> False
      }
    })
  assert completed == 1
  assert support.count("/protocol/openid-connect/token") == 1
  warden.stop(client)
}

pub fn userinfo_introspection_and_client_credentials_test() {
  let client = start()
  let s = session(client)
  let assert Ok(info) = warden.userinfo(client, s)
  assert warden.decode_userinfo(info, decode.at(["email"], decode.string))
    == Ok("alice@example.test")
  let assert Ok(#(token, _)) = warden.session_access_token(client, s)
  let assert Ok(warden.ActiveToken(details)) =
    warden.introspect(client, warden.access_token_value(token))
  assert details.subject == Some(warden.subject(warden.session_identity(s)))
  let assert Ok(warden.InactiveToken) = warden.introspect(client, "not-a-token")
  let assert Ok(cc) = warden.client_credentials(client, ["profile"])
  assert warden.access_token_value(cc.access_token) != ""
  assert option.is_some(cc.expires_in)
  warden.stop(client)
}

pub fn logout_ends_local_custody_and_provider_session_test() {
  let client = start()
  let s = session(client)
  let assert Ok(warden.RedirectToProvider(url)) =
    warden.logout(
      client,
      s,
      warden.LogoutOptions(
        post_logout_redirect_uri: Some("https://localhost:1/logged-out"),
        state: Some("bye"),
      ),
    )
  assert string.starts_with(url, issuer <> "/protocol/openid-connect/logout?")
  let assert Error(warden.SessionNotFound) =
    warden.restore_session(client, warden.session_reference(s))
  // Following the logout URL with the provider session cookie ends it and
  // returns to the post-logout URI with the state.
  let assert Ok(support.Query(query)) = support.keycloak_logout(url)
  let assert Ok(params) = uri.parse_query(query)
  assert list.key_find(params, "state") == Ok("bye")
  warden.stop(client)
}
