//// Session operations against the pinned Keycloak through Warden's API.

import gleam/dynamic/decode
import gleam/http/request
import gleam/list
import gleam/option.{Some}
import gleam/string
import gleam/uri
import warden
import warden/config
import warden_test_support as support

const issuer = "https://localhost:18443/realms/warden"

fn start() -> warden.Client {
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
  |> support.start_client
}

fn session(client: warden.Client) -> warden.Session {
  let assert Ok(redirect) =
    warden.begin_login(client, request.new(), warden.default_login())
  let assert Ok(support.Query(query)) =
    support.keycloak_login(
      warden.login_url(redirect),
      "alice",
      "alice-disposable",
    )
  let assert Ok(session) =
    warden.complete_login(client, support.query_callback(redirect, query))
  session
}

fn token(access: warden.Access) -> String {
  warden.access_token_value(access.token)
}

pub fn refresh_rotates_and_keeps_identity_test() {
  let client = start()
  let s0 = session(client)
  let assert Ok(a1) = warden.refresh(client, s0)
  assert warden.identity_key(warden.session_identity(a1.session))
    == warden.identity_key(warden.session_identity(s0))
  let assert Ok(a2) = warden.refresh(client, a1.session)
  assert token(a2) != token(a1)
  // The older session value reads the current token; it cannot dispatch the
  // rotated-out refresh token.
  support.count_reset()
  let assert Ok(current) = warden.refresh(client, s0)
  assert token(current) == token(a2)
  assert support.count("/protocol/openid-connect/token") == 0
  let assert Ok(info) = warden.userinfo(client, a2.session)
  assert warden.userinfo_subject(info)
    == warden.subject(warden.session_identity(a2.session))
  warden.stop(client)
}

pub fn concurrent_refresh_dispatches_once_test() {
  let client = start()
  let s0 = session(client)
  support.count_reset()
  let results =
    support.spawn_collect(
      list.repeat(fn() { warden.refresh(client, s0) }, 6),
      30_000,
    )
  let tokens =
    list.map(results, fn(r) {
      let assert Ok(access) = r
      token(access)
    })
  assert list.length(list.unique(tokens)) == 1
  assert support.count("/protocol/openid-connect/token") == 1
  warden.stop(client)
}

pub fn userinfo_introspection_and_client_credentials_test() {
  let client = start()
  let s = session(client)
  let assert Ok(info) = warden.userinfo(client, s)
  assert warden.decode_userinfo(info, decode.at(["email"], decode.string))
    == Ok("alice@example.test")
  let assert Ok(access) = warden.access_token(client, s)
  let assert Ok(warden.ActiveToken(details)) =
    warden.introspect(client, token(access))
  assert details.subject == Some(warden.subject(warden.session_identity(s)))
  let assert Ok(warden.InactiveToken) = warden.introspect(client, "not-a-token")
  let assert Ok(cc) = warden.client_credentials(client, ["profile"])
  assert warden.access_token_value(cc.access_token) != ""
  assert option.is_some(cc.expires_at)
  warden.stop(client)
}

pub fn logout_revokes_and_ends_the_provider_session_test() {
  let client = start()
  let s = session(client)
  let assert Ok(warden.LoggedOut(
    provider_logout: warden.RedirectToProvider(redirect),
    revocation: warden.Revoked,
  )) =
    warden.logout(
      client,
      s,
      warden.LogoutOptions(
        ..warden.default_logout(),
        post_logout_redirect_uri: Some("https://localhost:1/logged-out"),
        state: Some("bye"),
      ),
    )
  let url = warden.logout_url(redirect)
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
