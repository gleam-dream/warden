//// Interoperability with Ory Hydra v26.2.0 (`scripts/interop up`).
//// Hydra advertises S256, an end-session endpoint, a revocation endpoint
//// and no introspection endpoint in discovery (introspection is an admin
//// API there).

import gleam/http/request
import gleam/option.{Some}
import gleam/string
import warden
import warden/config
import warden_test_support as support

const issuer = "https://localhost:14444"

fn client() -> warden.Client {
  config.new(
    issuer:,
    client_id: "warden-rp",
    redirect_uri: "https://localhost:1/callback",
    authentication: config.ClientSecretBasic(config.secret(
      "warden-hydra-disposable-secret-0123456789",
    )),
  )
  |> config.with_scopes(["email", "offline_access"])
  |> config.with_trust(config.TrustAnchorsPem(support.ca_pem()))
  |> config.with_destinations(config.AllowLoopbackForTesting)
  |> support.start_client
}

fn login(client: warden.Client) -> warden.Session {
  let assert Ok(redirect) =
    warden.begin_login(client, request.new(), warden.default_login())
  // The consent app lives on another port of the same host.
  let assert Ok(support.Query(query)) =
    support.authorize(warden.login_url(redirect), "https://localhost:1444")
  let assert Ok(session) =
    warden.complete_login(client, support.query_callback(redirect, query))
  session
}

pub fn hydra_login_refresh_client_credentials_and_logout_test() {
  let client = client()
  let session = login(client)
  let identity = warden.session_identity(session)
  assert warden.issuer(identity) == issuer
  assert warden.subject(identity) == "alice-subject"
  assert warden.email(identity) == Some("alice@example.test")
  let assert Ok(info) = warden.userinfo(client, session)
  assert warden.userinfo_subject(info) == "alice-subject"
  let assert Ok(refreshed) = warden.refresh(client, session)
  let assert Ok(again) = warden.refresh(client, refreshed.session)
  // The first session value reads the current token instead of refreshing.
  let assert Ok(current) = warden.refresh(client, session)
  assert warden.access_token_value(current.token)
    == warden.access_token_value(again.token)
  let assert Ok(token) = warden.client_credentials(client, [])
  assert warden.access_token_value(token.access_token) != ""
  let assert Error(warden.IntrospectionNotSupported) =
    warden.introspect(client, warden.access_token_value(token.access_token))
  let assert Ok(warden.LoggedOut(
    provider_logout: warden.RedirectToProvider(redirect),
    revocation: warden.Revoked,
  )) =
    warden.logout(
      client,
      login(client),
      warden.LogoutOptions(
        ..warden.default_logout(),
        post_logout_redirect_uri: Some("https://localhost:1/logged-out"),
        state: Some("bye"),
      ),
    )
  assert string.starts_with(
    warden.logout_url(redirect),
    issuer <> "/oauth2/sessions/logout?",
  )
  warden.stop(client)
}
