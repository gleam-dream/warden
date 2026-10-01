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
