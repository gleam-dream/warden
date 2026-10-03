//// Interoperability with Dex v2.45.1 (`scripts/interop up`).
//// Dex advertises S256 PKCE, no RFC 9207 `iss` and no end-session endpoint.

import gleam/http/request
import gleam/option.{Some}
import warden
import warden/config
import warden_test_support as support

const issuer = "https://localhost:15556/dex"

fn client() -> warden.Client {
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
  |> support.start_client
}

fn login(client: warden.Client) -> warden.Session {
  let assert Ok(redirect) =
    warden.begin_login(client, request.new(), warden.default_login())
  let assert Ok(support.Query(query)) =
    support.form_login(warden.login_url(redirect), issuer, [
      #("login", "alice@example.test"),
      #("password", "alice-disposable"),
    ])
  let assert Ok(session) =
    warden.complete_login(client, support.query_callback(redirect, query))
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
  let assert Ok(refreshed) = warden.refresh(client, session)
  let assert Ok(_) = warden.refresh(client, refreshed.session)
  let assert Ok(warden.LoggedOut(
    provider_logout: warden.NoEndSessionEndpoint,
    ..,
  )) = warden.logout(client, login(client), warden.default_logout())
  warden.stop(client)
}
