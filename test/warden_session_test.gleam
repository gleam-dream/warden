//// Session operations against the scripted provider: refresh reservation,
//// rotation, retention, continuity, quarantine and publication recovery;
//// userinfo, client credentials, introspection and logout.

import gleam/dynamic/decode
import gleam/erlang/process
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import warden
import warden/config
import warden/internal/custody_store
import warden_login_test.{logged_in, settings, start}
import warden_test_support as support

fn refresh_token_of(provider: support.Provider) -> String {
  let assert [token] = support.refresh_tokens(provider)
  token
}

pub fn refresh_rotates_and_advances_revision_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let first = refresh_token_of(provider)
  let assert Ok(#(access1, _)) = warden.session_access_token(client, session)
  let assert Ok(warden.RefreshCompleted(refreshed)) =
    warden.refresh_session(client, session)
  assert warden.session_revision(refreshed) == 2
  assert warden.session_reference(refreshed)
    == warden.session_reference(session)
  assert warden.identity_key(warden.session_identity(refreshed))
    == warden.identity_key(warden.session_identity(session))
  // The provider rotated; custody holds the successor.
  assert refresh_token_of(provider) != first
  let assert Ok(#(access2, _)) = warden.session_access_token(client, refreshed)
  assert warden.access_token_value(access1)
    != warden.access_token_value(access2)
  // The superseded session value is stale.
  let assert Error(warden.RefreshSessionStale) =
    warden.refresh_session(client, session)
  let assert Error(warden.SessionStale) =
    warden.session_access_token(client, session)
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn concurrent_refresh_sends_one_request_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  support.script(
    provider,
    support.Refresh(refresh_token_of(provider)),
    support.Delay(300),
  )
  let attempt = fn() { warden.refresh_session(client, session) }
  let results = support.spawn_collect(list.repeat(attempt, 8), 30_000)
  let completed =
    list.count(results, fn(r) {
      case r {
        Ok(warden.RefreshCompleted(_)) -> True
        _ -> False
      }
    })
  let busy_or_stale =
    list.count(results, fn(r) {
      r == Error(warden.RefreshInProgress)
      || r == Error(warden.RefreshSessionStale)
    })
  assert completed == 1
  assert busy_or_stale == 7
  // One authorization-code request plus one refresh request.
  assert support.token_requests(provider) == 2
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn omitted_refresh_token_is_retained_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let original = refresh_token_of(provider)
  support.script(provider, support.Refresh(original), support.DropRefreshToken)
  let assert Ok(warden.RefreshCompleted(refreshed)) =
    warden.refresh_session(client, session)
  // Custody retained the original token, which the provider still accepts.
  let assert Ok(warden.RefreshCompleted(_)) =
    warden.refresh_session(client, refreshed)
  assert support.token_requests(provider) == 3
  warden.stop(client)
  support.provider_stop(provider)
}

fn refresh_with(
  behaviour: support.Behaviour,
) -> #(warden.RefreshResult, Result(warden.RefreshResult, warden.RefreshError)) {
  let provider = support.provider_start(support.Standard)
  let client =
    start(
      settings(provider)
      |> config.with_transport(
        config.Transport(..config.default_transport(), request_timeout_ms: 400)
        |> fn(t) {
          config.Transport(
            ..t,
            trust: config.TrustAnchorsPem(support.ca_pem()),
            destinations: config.AllowLoopbackForTesting,
          )
        },
      ),
    )
  let session = logged_in(provider, client)
  support.script(
    provider,
    support.Refresh(refresh_token_of(provider)),
    behaviour,
  )
  let assert Ok(first) = warden.refresh_session(client, session)
  let second = warden.refresh_session(client, session)
  warden.stop(client)
  support.provider_stop(provider)
  #(first, second)
}

pub fn uncertain_and_invalid_refresh_outcomes_quarantine_test() {
  let quarantined = fn(result) {
    case result {
      warden.RefreshProviderQuarantined(_) -> "provider"
      warden.RefreshResponseQuarantined(problem, _) -> string.inspect(problem)
      other -> "unexpected " <> string.inspect(other)
    }
  }
  let cases = [
    #(support.Delay(1500), "provider"),
    #(support.Status(503, "temporarily_unavailable"), "provider"),
    #(support.Close, "provider"),
    #(support.MalformedJson, "RefreshResponseMalformed"),
    // Tokens Warden cannot use as Bearer tokens, or a negative lifetime
    // (review finding J12).
    #(support.TokenField("token_type", "DPoP"), "RefreshResponseMalformed"),
    #(support.TokenIntField("expires_in", -5), "RefreshResponseMalformed"),
    // An error code Warden does not recognise may follow processing of the
    // grant; the token it sent is never sent again (F6).
    #(support.Status(400, "unrecognised_error"), "provider"),
    #(support.IdToken("changed_sub"), "RefreshedSubjectMismatch"),
    #(support.IdToken("changed_nonce"), "RefreshedNonceMismatch"),
    #(
      support.IdToken("changed_auth_time"),
      "RefreshedAuthenticationTimeMismatch",
    ),
    #(
      support.IdToken("wrong_aud"),
      "RefreshedIdTokenInvalid(IdTokenAudienceMismatch)",
    ),
  ]
  list.each(cases, fn(c) {
    let #(first, second) = refresh_with(c.0)
    assert #(c.0, quarantined(first)) == #(c.0, c.1)
    // A quarantined generation never dispatches again.
    assert second == Error(warden.RefreshQuarantined)
  })
}

pub fn definite_rejection_revokes_or_releases_test() {
  let #(first, second) = refresh_with(support.Status(400, "invalid_grant"))
  assert first == warden.RefreshRejectedByEndpoint(warden.InvalidGrant)
  assert second == Error(warden.RefreshRevoked)
  // A rejection that does not concern the grant releases the generation.
  let #(first, second) = refresh_with(support.Status(401, "invalid_client"))
  assert first == warden.RefreshRejectedByEndpoint(warden.InvalidClient)
  let assert Ok(warden.RefreshCompleted(_)) = second
}

pub fn bearer_token_type_is_case_insensitive_test() {
  let #(first, _) = refresh_with(support.TokenField("token_type", "bearer"))
  let assert warden.RefreshCompleted(_) = first
}

pub fn proven_no_send_releases_the_generation_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  support.provider_stop(provider)
  let assert Ok(warden.RefreshDidNotSend(warden.TransportFailure(
    sent: False,
    reason: warden.ConnectionRefused,
  ))) = warden.refresh_session(client, session)
  // Released, not quarantined: another attempt is admitted.
  let assert Ok(warden.RefreshDidNotSend(_)) =
    warden.refresh_session(client, session)
  warden.stop(client)
}

pub fn lost_publication_acknowledgement_recovers_without_provider_test() {
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
  let requests = support.token_requests(provider)
  support.sleep(600)
  let assert Ok(Nil) =
    custody_store.delay_replies(
      warden.custody_owner(client),
      custody_store.DelayNothing,
      0,
    )
  let assert Ok(warden.RefreshCompleted(recovered)) =
    warden.recover_refresh_publication(client, recovery)
  let assert Ok(warden.RefreshCompleted(again)) =
    warden.recover_refresh_publication(client, recovery)
  assert warden.session_revision(recovered) == 2
  assert warden.session_revision(again) == 2
  assert support.token_requests(provider) == requests
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn foreign_sessions_are_rejected_before_any_call_test() {
  let provider_a = support.provider_start(support.Standard)
  let provider_b = support.provider_start(support.Standard)
  let a = start(settings(provider_a))
  let b = start(settings(provider_b))
  let session = logged_in(provider_a, a)
  let requests = support.token_requests(provider_b)
  let assert Error(warden.RefreshSessionForeign) =
    warden.refresh_session(b, session)
  let assert Error(warden.UserinfoSession(warden.SessionForeign)) =
    warden.userinfo(b, session)
  assert support.token_requests(provider_b) == requests
  warden.stop(a)
  warden.stop(b)
  support.provider_stop(provider_a)
  support.provider_stop(provider_b)
}

pub fn userinfo_requires_subject_continuity_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let assert Ok(info) = warden.userinfo(client, session)
  assert warden.userinfo_subject(info) == "subject-1"
  assert warden.decode_userinfo(info, decode.at(["email"], decode.string))
    == Ok("user@example.test")
  support.script(provider, support.Userinfo, support.Sub("someone-else"))
  let assert Error(warden.UserinfoSubjectMismatch) =
    warden.userinfo(client, session)
  support.script(
    provider,
    support.Userinfo,
    support.Status(401, "invalid_token"),
  )
  let assert Error(warden.UserinfoFailed(warden.ProviderStatus(
    status: 401,
    error: warden.InvalidToken,
  ))) = warden.userinfo(client, session)
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn client_credentials_returns_typed_token_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let assert Ok(token) = warden.client_credentials(client, ["api"])
  assert warden.access_token_value(token.access_token) != ""
  assert token.expires_in == Some(60)
  let assert Error(warden.ClientCredentialsInvalidScope(_)) =
    warden.client_credentials(client, ["a b"])
  warden.stop(client)
  let public =
    start(
      config.Settings(..settings(provider), authentication: config.PublicClient),
    )
  let assert Error(warden.ClientCredentialsNeedConfidentialClient) =
    warden.client_credentials(public, [])
  warden.stop(public)
  support.provider_stop(provider)
}

pub fn introspection_distinguishes_inactive_from_failure_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let assert Ok(warden.ActiveToken(info)) =
    warden.introspect(client, "active-token")
  assert info.client_id == Some("warden-rp")
  assert info.subject == Some("subject-1")
  assert info.scopes == ["openid", "email"]
  assert decode.run(info.claims, decode.at(["department"], decode.string))
    == Ok("platform")
  let assert Ok(warden.InactiveToken) = warden.introspect(client, "unknown")
  support.provider_stop(provider)
  let assert Error(warden.IntrospectionFailed(warden.TransportFailure(
    sent: False,
    ..,
  ))) = warden.introspect(client, "active-token")
  warden.stop(client)
}

pub fn logout_removes_custody_then_redirects_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let assert Ok(warden.RedirectToProvider(url)) =
    warden.logout(
      client,
      session,
      warden.LogoutOptions(
        post_logout_redirect_uri: Some("https://app.example/logged-out"),
        state: Some("logout-state"),
      ),
    )
  assert string.starts_with(
    url,
    support.provider_issuer(provider) <> "/logout?",
  )
  assert string.contains(url, "id_token_hint=")
  assert string.contains(url, "post_logout_redirect_uri=")
  assert string.contains(url, "state=logout-state")
  let assert Error(warden.SessionNotFound) =
    warden.restore_session(client, warden.session_reference(session))
  let assert Error(warden.RefreshSessionMissing) =
    warden.refresh_session(client, session)
  let assert Error(warden.InvalidPostLogoutRedirect) =
    warden.logout(
      client,
      logged_in(provider, client),
      warden.LogoutOptions(
        post_logout_redirect_uri: Some("javascript:alert(1)"),
        state: None,
      ),
    )
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn logout_without_end_session_endpoint_is_explicit_test() {
  let provider = support.provider_start(support.NoEndSession)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let assert Ok(warden.NoEndSessionEndpoint) =
    warden.logout(
      client,
      session,
      warden.LogoutOptions(post_logout_redirect_uri: None, state: None),
    )
  let assert Error(warden.SessionNotFound) =
    warden.restore_session(client, warden.session_reference(session))
  warden.stop(client)
  support.provider_stop(provider)
}

/// The custody owner is unavailable: refresh never reaches the provider and
/// reports a typed unresolved reservation; after the owner restarts empty,
/// the session is gone rather than silently re-created.
pub fn custody_loss_during_refresh_never_calls_the_provider_test() {
  let provider = support.provider_start(support.Standard)
  let client =
    start(config.Settings(..settings(provider), store_timeout_ms: 300))
  let session = logged_in(provider, client)
  let requests = support.token_requests(provider)
  let owner = warden.custody_owner(client)
  let assert Ok(pid) = process.subject_owner(owner.subject)
  process.kill(pid)
  let first = warden.refresh_session(client, session)
  case first {
    Ok(warden.RefreshReservationUnresolved(_))
    | Error(warden.RefreshSessionMissing) -> Nil
    other -> panic as string.inspect(other)
  }
  support.sleep(100)
  let assert Error(warden.RefreshSessionMissing) =
    warden.refresh_session(client, session)
  assert support.token_requests(provider) == requests
  warden.stop(client)
  support.provider_stop(provider)
}

/// OIDC Core §12.2 permits a refresh response without an ID token. The
/// native backend keeps the established identity (decision D10); the pinned
/// oidcc backend cannot accept the response and quarantines (D6).
pub fn refresh_without_id_token_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  support.script(
    provider,
    support.Refresh(refresh_token_of(provider)),
    support.OmitIdToken,
  )
  let assert Ok(warden.RefreshCompleted(refreshed)) =
    warden.refresh_session(client, session)
  assert warden.identity_key(warden.session_identity(refreshed))
    == warden.identity_key(warden.session_identity(session))
  assert warden.session_revision(refreshed) == 2
  let assert Ok(warden.RefreshCompleted(_)) =
    warden.refresh_session(client, refreshed)

  warden.stop(client)
  support.provider_stop(provider)
}

/// A refresh whose dispatching process dies mid-request may already have
/// reached the provider: the generation is quarantined, not left "in
/// progress" forever (review finding F7).
pub fn a_dispatcher_that_dies_quarantines_the_generation_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  support.script(
    provider,
    support.Refresh(refresh_token_of(provider)),
    support.Delay(3000),
  )
  let dispatcher =
    process.spawn_unlinked(fn() { warden.refresh_session(client, session) })
  process.sleep(300)
  process.kill(dispatcher)
  process.sleep(100)
  assert warden.refresh_session(client, session)
    == Error(warden.RefreshQuarantined)
  warden.stop(client)
  support.provider_stop(provider)
}

/// The orphaned generation still accepts its own publication recovery: a
/// handler may return RefreshPublicationUnresolved and exit before another
/// process recovers it.
pub fn publication_recovery_survives_the_dispatcher_test() {
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
  let handed_over = process.new_subject()
  process.spawn_unlinked(fn() {
    let assert Ok(warden.RefreshPublicationUnresolved(recovery)) =
      warden.refresh_session(client, session)
    process.send(handed_over, recovery)
  })
  let assert Ok(recovery) = process.receive(handed_over, 2000)
  support.sleep(600)
  let assert Ok(Nil) =
    custody_store.delay_replies(
      warden.custody_owner(client),
      custody_store.DelayNothing,
      0,
    )
  let assert Ok(warden.RefreshCompleted(refreshed)) =
    warden.recover_refresh_publication(client, recovery)
  assert warden.session_revision(refreshed) == 2
  warden.stop(client)
  support.provider_stop(provider)
}
