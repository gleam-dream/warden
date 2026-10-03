//// Public values never reveal secrets through `string.inspect`, `echo` or
//// crash reports: client credentials, sealing keys, browser bindings,
//// session references, raw claims, tokens and redirect URLs carrying an ID
//// token (internal security review, findings C1 and F3).

import gleam/dict
import gleam/http/response
import gleam/list
import gleam/option
import gleam/string
import gleam/time/duration
import warden
import warden/config
import warden/internal/custody
import warden/testing
import warden_login_test.{authorize, browser, logged_in, settings, start}
import warden_store_support as faults
import warden_test_support as support

fn tokens_of(client: warden.Client, session: warden.Session) -> List(String) {
  let assert Ok(snapshot) =
    custody.get(client.custody, warden.session_reference(session))
  let tokens = snapshot.entry.tokens
  [
    tokens.access_token,
    ..option.values([tokens.refresh_token, tokens.id_token])
  ]
}

fn binding_of(redirect: warden.LoginRedirect) -> String {
  let assert Ok(cookie) =
    response.get_header(
      warden.login_response(response.new(200), redirect),
      "set-cookie",
    )
  let assert Ok(#(pair, _)) = string.split_once(cookie, ";")
  let assert Ok(#(_, value)) = string.split_once(pair, "=")
  value
}

fn assert_hidden(value: a, secrets: List(String)) -> Nil {
  let printed = string.inspect(value)
  list.each(secrets, fn(secret) {
    assert #(secret, string.contains(printed, secret)) == #(secret, False)
  })
}

pub fn client_session_and_redirect_do_not_inspect_secrets_test() {
  let provider = support.provider_start(support.Standard)
  support.set_claims(provider, dict.from_list([#("name", "SENTINEL-CLAIM")]))
  let client = start(settings(provider))
  let assert Ok(redirect) =
    warden.begin_login(client, browser(), warden.default_login())
  let binding = binding_of(redirect)
  let assert Ok(session) =
    warden.complete_login(client, authorize(provider, redirect, "inspect-code"))
  let secrets = [
    "sentinel-secret",
    "SENTINEL-CLAIM",
    binding,
    warden.login_url(redirect),
    warden.session_reference(session),
    ..tokens_of(client, session)
  ]
  assert_hidden(
    #(client, redirect, session, warden.session_identity(session)),
    secrets,
  )
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn private_key_credential_does_not_inspect_test() {
  let provider = support.provider_start(support.Standard)
  let jwk = support.client_private_jwk()
  let assert Ok(key) = config.signing_key_from_jwk(jwk)
  let assert Ok(client) =
    warden.new(config.new(
      issuer: support.provider_issuer(provider),
      client_id: "warden-rp",
      redirect_uri: "https://app.example/callback",
      authentication: config.PrivateKeyJwt(key),
    ))
  let assert Ok(d) = support.jwk_private_member(jwk)
  assert_hidden(client, [d])
  support.provider_stop(provider)
}

fn durable(provider: support.Provider) -> #(warden.Client, faults.Control) {
  let #(custody_store, control) = faults.memory()
  let client =
    start(
      settings(provider)
      |> config.with_store_timeout(duration.milliseconds(200))
      |> config.with_custody_store(custody_store)
      |> config.with_sealing_key(faults.sealing_key()),
    )
  #(client, control)
}

pub fn recovery_values_do_not_inspect_tokens_test() {
  let provider = support.provider_start(support.Standard)
  let #(client, control) = durable(provider)
  let session = logged_in(provider, client)
  faults.lose_ack_of(control, 2)
  let assert Error(warden.RefreshUnconfirmed(recovery) as error) =
    warden.refresh(client, session)
  let assert Ok(refreshed) = warden.recover_refresh(client, recovery)
  assert_hidden(#(recovery, error), [
    warden.session_reference(session),
    ..tokens_of(client, refreshed.session)
  ])
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn installation_recovery_does_not_inspect_tokens_test() {
  let provider = support.provider_start(support.Standard)
  let #(client, control) = durable(provider)
  let assert Ok(redirect) =
    warden.begin_login(client, browser(), warden.default_login())
  let request = authorize(provider, redirect, "inspect-recovery-code")
  faults.lose_ack_of(control, 1)
  let assert Error(warden.CustodyUnconfirmed(recovery)) =
    warden.complete_login(client, request)
  let assert Ok(session) = warden.recover_custody(client, recovery)
  assert_hidden(recovery, [
    warden.session_reference(session),
    ..tokens_of(client, session)
  ])
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn configuration_and_credentials_do_not_inspect_test() {
  let provider = support.provider_start(support.Standard)
  let jwk = support.client_private_jwk()
  let assert Ok(d) = support.jwk_private_member(jwk)
  let assert Ok(key) = config.signing_key_from_jwk(jwk)
  let jwt_secret = "SENTINEL-JWT-SECRET-0123456789-abcdefghijklmnop"
  let secrets = ["sentinel-secret", jwt_secret, d]
  let with = fn(authentication) {
    config.new(
      issuer: support.provider_issuer(provider),
      client_id: "warden-rp",
      redirect_uri: "https://app.example/callback",
      authentication:,
    )
  }
  let configured = [
    settings(provider),
    with(config.ClientSecretPost(config.secret("sentinel-secret"))),
    with(config.ClientSecretJwt(config.secret(jwt_secret))),
    with(config.PrivateKeyJwt(key)),
  ]
  list.each(configured, fn(configuration) {
    assert_hidden(configuration, secrets)
    let assert Ok(client) = warden.new(configuration)
    assert_hidden(client, secrets)
  })
  assert_hidden(#(config.secret("sentinel-secret"), key), secrets)
  support.provider_stop(provider)
}

pub fn tokens_and_introspection_do_not_inspect_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let session_tokens = tokens_of(client, session)
  let assert Ok(access) = warden.access_token(client, session)
  let assert Ok(refreshed) = warden.refresh(client, session)
  let assert Ok(client_token) = warden.client_credentials(client, ["api"])
  let introspected = warden.introspect(client, "active-token")
  let assert Ok(warden.ActiveToken(_)) = introspected
  let inactive = warden.introspect(client, "SENTINEL-INACTIVE-TOKEN")
  let assert Ok(warden.InactiveToken) = inactive
  let secrets =
    list.flatten([
      ["sentinel-secret", "active-token", "SENTINEL-INACTIVE-TOKEN"],
      [
        warden.access_token_value(access.token),
        warden.access_token_value(client_token.access_token),
      ],
      session_tokens,
      tokens_of(client, refreshed.session),
    ])
  assert_hidden(
    #(access, refreshed, client_token, introspected, inactive),
    secrets,
  )
  support.provider_stop(provider)
  let failed = warden.introspect(client, "active-token")
  let assert Error(warden.IntrospectionFailed(_)) = failed
  let denied = warden.client_credentials(client, ["api"])
  let assert Error(_) = denied
  assert_hidden(#(failed, denied), secrets)
  warden.stop(client)
}

/// The follow-up from wave 1: the provider logout redirect embeds the ID
/// token as `id_token_hint`, so the outcome holds it in a closure.
pub fn logout_redirect_does_not_inspect_the_id_token_test() {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  let assert Ok(client) =
    warden.new(testing.config(provider, "https://app.test/callback"))
  let assert Ok(Nil) = warden.start(client)
  let assert Ok(redirect) =
    warden.begin_login(client, browser(), warden.default_login())
  let assert Ok(callback) =
    testing.authorize(provider, redirect, subject: "ada")
  let assert Ok(session) = warden.complete_login(client, callback)
  let assert Ok(snapshot) =
    custody.get(client.custody, warden.session_reference(session))
  let assert option.Some(id_token) = snapshot.entry.tokens.id_token
  let assert Ok(
    warden.LoggedOut(provider_logout: warden.RedirectToProvider(logout), ..) as outcome,
  ) = warden.logout(client, session, warden.default_logout())
  assert string.contains(warden.logout_url(logout), id_token)
  assert_hidden(outcome, [id_token, warden.logout_url(logout)])
  let reply = warden.logout_response(response.new(200), logout)
  assert reply.status == 303
  assert response.get_header(reply, "location") == Ok(warden.logout_url(logout))
  warden.stop(client)
  testing.stop_provider(provider)
}
