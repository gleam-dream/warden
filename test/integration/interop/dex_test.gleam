//// Interoperability with Dex v2.45.1 (`scripts/interop up`).
//// Dex advertises S256 PKCE, no RFC 9207 `iss` and no end-session endpoint.

import gleam/option.{None, Some}
import warden
import warden/config
import warden_test_support as support

const issuer = "https://localhost:15556/dex"

fn client() -> warden.Client {
  let assert Ok(validated) =
    config.new(
      issuer:,
      client_id: "warden-rp",
      redirect_uri: "https://localhost:1/callback",
      authentication: config.ClientSecretBasic(config.secret(
        "warden-dex-disposable-secret",
      )),
    )
    |> config.with_scopes(["email", "profile", "offline_access"])
    |> config.with_trust(config.TrustAnchorsPem(support.ca_pem()))
    |> config.with_destinations(config.AllowLoopbackForTesting)
    |> config.validate
  let assert Ok(client) = warden.start(validated)
  client
}

fn login(client: warden.Client) -> warden.Session {
  let assert Ok(redirect) =
    warden.begin_login(client, None, warden.default_login())
  let assert Ok(support.Query(query)) =
    support.form_login(redirect.url, issuer, [
      #("login", "alice@example.test"),
      #("password", "alice-disposable"),
    ])
  let assert Ok(warden.LoginCompleted(session)) =
    warden.complete_login(
      client,
      warden.QueryCallback(query),
      Some(redirect.browser_binding),
    )
  session
}

pub fn dex_login_refresh_userinfo_and_logout_test() {
  let client = client()
  let session = login(client)
  let identity = warden.session_identity(session)
  assert warden.issuer(identity) == issuer
  assert warden.email(identity) == Some("alice@example.test")
  let assert Ok(info) = warden.userinfo(client, session)
  assert warden.userinfo_subject(info) == warden.subject(identity)
  let assert Ok(warden.RefreshCompleted(refreshed)) =
    warden.refresh_session(client, session)
  assert warden.session_revision(refreshed) == 2
  let assert Ok(warden.RefreshCompleted(_)) =
    warden.refresh_session(client, refreshed)
  let assert Ok(warden.NoEndSessionEndpoint) =
    warden.logout(
      client,
      login(client),
      warden.LogoutOptions(post_logout_redirect_uri: None, state: None),
    )
  warden.stop(client)
}
