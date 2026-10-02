//// Public values never reveal secrets through `string.inspect`, `echo` or
//// crash reports: client credentials, browser bindings, session references,
//// raw claims and tokens (internal security review, findings C1 and F3).

import gleam/dict
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import warden
import warden/config
import warden/internal/custody_store
import warden_login_test.{authorize, logged_in, settings, start}
import warden_test_support as support

fn tokens_of(client: warden.Client, session: warden.Session) -> List(String) {
  let assert Ok(Ok(snapshot)) =
    custody_store.get(
      warden.custody_owner(client),
      warden.session_reference(session),
    )
  let tokens = snapshot.tokens
  [
    tokens.access_token,
    ..option.values([tokens.refresh_token, tokens.id_token])
  ]
}

fn assert_hidden(value: a, secrets: List(String)) -> Nil {
  let printed = string.inspect(value)
  list.each(secrets, fn(secret) {
    assert #(secret, string.contains(printed, secret)) == #(secret, False)
  })
}

pub fn client_session_and_binding_do_not_inspect_secrets_test() {
  let provider = support.provider_start(support.Standard)
  support.set_claims(provider, dict.from_list([#("name", "SENTINEL-CLAIM")]))
  let client = start(settings(provider))
  let assert Ok(redirect) =
    warden.begin_login(client, None, warden.default_login())
  let query = authorize(provider, redirect, "inspect-code")
  let assert Ok(warden.LoginCompleted(session)) =
    warden.complete_login(
      client,
      warden.QueryCallback(query),
      Some(redirect.browser_binding),
    )
  let secrets = [
    "sentinel-secret",
    "SENTINEL-CLAIM",
    warden.browser_binding_value(redirect.browser_binding),
    warden.session_reference(session),
    ..tokens_of(client, session)
  ]
  assert_hidden(
    #(
      client,
      redirect.browser_binding,
      session,
      warden.session_identity(session),
    ),
    secrets,
  )
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn private_key_credential_does_not_inspect_test() {
  let provider = support.provider_start(support.Standard)
  let jwk = support.client_private_jwk()
  let assert Ok(key) = config.signing_key_from_jwk(jwk)
  let client =
    start(
      config.Settings(
        ..settings(provider),
        authentication: config.PrivateKeyJwt(key),
      ),
    )
  let assert Ok(d) = support.jwk_private_member(jwk)
  assert_hidden(client, [d])
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn recovery_values_do_not_inspect_tokens_test() {
  let provider = support.provider_start(support.Standard)
  let client =
    start(config.Settings(..settings(provider), store_timeout_ms: 200))
  let session = logged_in(provider, client)
  let assert Ok(Nil) =
    custody_store.delay_replies(
      warden.custody_owner(client),
      custody_store.DelayPublish,
      500,
    )
  let assert Ok(warden.RefreshPublicationUnresolved(recovery)) =
    warden.refresh_session(client, session)
  support.sleep(600)
  let assert Ok(Nil) =
    custody_store.delay_replies(
      warden.custody_owner(client),
      custody_store.DelayNothing,
      0,
    )
  let assert Ok(warden.RefreshCompleted(refreshed)) =
    warden.recover_refresh_publication(client, recovery)
  assert_hidden(recovery, [
    warden.session_reference(session),
    ..tokens_of(client, refreshed)
  ])
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn installation_recovery_does_not_inspect_tokens_test() {
  let provider = support.provider_start(support.Standard)
  let client =
    start(config.Settings(..settings(provider), store_timeout_ms: 200))
  let assert Ok(Nil) =
    custody_store.delay_replies(
      warden.custody_owner(client),
      custody_store.DelayInstall,
      500,
    )
  let assert Ok(redirect) =
    warden.begin_login(client, None, warden.default_login())
  let query = authorize(provider, redirect, "inspect-recovery-code")
  let assert Ok(warden.LoginRecoveryRequired(recovery)) =
    warden.complete_login(
      client,
      warden.QueryCallback(query),
      Some(redirect.browser_binding),
    )
  support.sleep(600)
  let assert Ok(Nil) =
    custody_store.delay_replies(
      warden.custody_owner(client),
      custody_store.DelayNothing,
      0,
    )
  let assert Ok(warden.CustodyRecovered(session)) =
    warden.recover_custody(client, recovery)
  assert_hidden(recovery, tokens_of(client, session))
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
  let configured = [
    settings(provider),
    config.Settings(
      ..settings(provider),
      authentication: config.ClientSecretPost(config.secret("sentinel-secret")),
    ),
    config.Settings(
      ..settings(provider),
      authentication: config.ClientSecretJwt(config.secret(jwt_secret)),
    ),
    config.Settings(
      ..settings(provider),
      authentication: config.PrivateKeyJwt(key),
    ),
  ]
  list.each(configured, fn(settings) {
    assert_hidden(settings, secrets)
    let assert Ok(validated) = config.validate(settings)
    assert_hidden(validated, secrets)
  })
  assert_hidden(#(config.secret("sentinel-secret"), key), secrets)
  support.provider_stop(provider)
}

pub fn tokens_token_responses_and_introspection_do_not_inspect_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let session_tokens = tokens_of(client, session)
  let assert Ok(#(access, _) as access_result) =
    warden.session_access_token(client, session)
  let assert Ok(refreshed) = warden.refresh_session(client, session)
  let assert warden.RefreshCompleted(refreshed_session) = refreshed
  let assert Ok(client_token) = warden.client_credentials(client, ["api"])
  let introspected = warden.introspect(client, "active-token")
  let assert Ok(warden.ActiveToken(_)) = introspected
  let inactive = warden.introspect(client, "SENTINEL-INACTIVE-TOKEN")
  let assert Ok(warden.InactiveToken) = inactive
  let secrets =
    list.flatten([
      ["sentinel-secret", "active-token", "SENTINEL-INACTIVE-TOKEN"],
      [
        warden.access_token_value(access),
        warden.access_token_value(client_token.access_token),
      ],
      session_tokens,
      tokens_of(client, refreshed_session),
    ])
  assert_hidden(
    #(access, access_result, refreshed, client_token, introspected, inactive),
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
