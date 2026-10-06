//// Session operations against the scripted provider: access with the
//// refresh margin, one refresh shared by concurrent requests, rotation,
//// retention, continuity, quarantine and publication recovery; userinfo,
//// client credentials, introspection and logout.

import gleam/dynamic/decode
import gleam/erlang/process
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleam/time/duration
import gleam/time/timestamp
import warden
import warden/config
import warden_login_test.{browser, logged_in, settings, start, with_clock}
import warden_store_support as faults
import warden_test_support as support

fn refresh_token_of(provider: support.Provider) -> String {
  let assert [token] = support.refresh_tokens(provider)
  token
}

fn token(access: warden.Access) -> String {
  warden.access_token_value(access.token)
}

pub fn refresh_rotates_and_reports_the_new_token_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let first = refresh_token_of(provider)
  let assert Ok(before) = warden.access_token(client, session)
  let assert Ok(after) = warden.refresh(client, session)
  assert warden.session_reference(after.session)
    == warden.session_reference(session)
  assert warden.identity_key(warden.session_identity(after.session))
    == warden.identity_key(warden.session_identity(session))
  // The provider rotated; custody holds the successor.
  assert refresh_token_of(provider) != first
  assert token(before) != token(after)
  // The superseded session value is not stale: it reads the current token,
  // and a forced refresh with it sends nothing, because the session was
  // already refreshed since that value was read.
  let requests = support.token_requests(provider)
  let assert Ok(current) = warden.access_token(client, session)
  assert token(current) == token(after)
  let assert Ok(again) = warden.refresh(client, session)
  assert token(again) == token(after)
  assert support.token_requests(provider) == requests
  warden.stop(client)
  support.provider_stop(provider)
}

/// Concurrent requests share one refresh; the losers wait for it
/// and receive its token instead of an error.
pub fn concurrent_refresh_sends_one_request_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  support.script(
    provider,
    support.Refresh(refresh_token_of(provider)),
    support.Delay(300),
  )
  let attempt = fn() { warden.refresh(client, session) }
  let results = support.spawn_collect(list.repeat(attempt, 8), 30_000)
  let tokens =
    list.map(results, fn(r) {
      let assert Ok(access) = r
      token(access)
    })
    |> list.unique
  assert list.length(tokens) == 1
  // One authorization-code request plus one refresh request.
  assert support.token_requests(provider) == 2
  warden.stop(client)
  support.provider_stop(provider)
}

/// A token within the refresh margin is refreshed by `access_token`; one
/// outside it is returned as is.
pub fn access_token_refreshes_within_the_margin_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let assert Ok(fresh) = warden.access_token(client, session)
  assert option.is_some(fresh.expires_at)
  assert support.token_requests(provider) == 1
  // The next token lives 10 s: inside the default 30 s margin.
  support.script(
    provider,
    support.Refresh(refresh_token_of(provider)),
    support.TokenIntField("expires_in", 10),
  )
  let assert Ok(short) = warden.refresh(client, session)
  assert support.token_requests(provider) == 2
  let assert Ok(renewed) = warden.access_token(client, short.session)
  assert token(renewed) != token(short)
  assert support.token_requests(provider) == 3
  // With a zero margin the same short token is used as is.
  warden.stop(client)
  let relaxed =
    start(settings(provider) |> config.with_refresh_margin(duration.seconds(0)))
  let session = logged_in(provider, relaxed)
  support.script(
    provider,
    support.Refresh(refresh_token_of_latest(provider)),
    support.TokenIntField("expires_in", 10),
  )
  let assert Ok(short) = warden.refresh(relaxed, session)
  let requests = support.token_requests(provider)
  let assert Ok(same) = warden.access_token(relaxed, short.session)
  assert token(same) == token(short)
  assert support.token_requests(provider) == requests
  warden.stop(relaxed)
  support.provider_stop(provider)
}

fn refresh_token_of_latest(provider: support.Provider) -> String {
  let assert Ok(token) = list.last(support.refresh_tokens(provider))
  token
}

/// A request that finds another's refresh in flight waits at most the
/// refresh wait, then answers `RefreshWaitTimedOut` without sending.
pub fn refresh_wait_is_bounded_test() {
  let provider = support.provider_start(support.Standard)
  let client =
    start(
      settings(provider)
      |> config.with_refresh_wait(duration.milliseconds(200)),
    )
  let session = logged_in(provider, client)
  support.script(
    provider,
    support.Refresh(refresh_token_of(provider)),
    support.Delay(1500),
  )
  let winner = process.new_subject()
  process.spawn(fn() { process.send(winner, warden.refresh(client, session)) })
  process.sleep(100)
  assert warden.refresh(client, session) == Error(warden.RefreshWaitTimedOut)
  assert warden.session_error_action(warden.RefreshWaitTimedOut)
    == warden.RetryLater
  let assert Ok(Ok(_)) = process.receive(winner, 5000)
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
  let assert Ok(refreshed) = warden.refresh(client, session)
  // Custody retained the original token, which the provider still accepts.
  let assert Ok(_) = warden.refresh(client, refreshed.session)
  assert support.token_requests(provider) == 3
  warden.stop(client)
  support.provider_stop(provider)
}

fn refresh_with(
  behaviour: support.Behaviour,
) -> #(
  Result(warden.Access, warden.SessionError),
  Result(warden.Access, warden.SessionError),
) {
  let provider = support.provider_start(support.Standard)
  let client =
    start(
      settings(provider)
      |> config.with_request_timeout(duration.milliseconds(400)),
    )
  let session = logged_in(provider, client)
  support.script(
    provider,
    support.Refresh(refresh_token_of(provider)),
    behaviour,
  )
  let first = warden.refresh(client, session)
  let second = warden.refresh(client, session)
  warden.stop(client)
  support.provider_stop(provider)
  #(first, second)
}

pub fn uncertain_and_invalid_refresh_outcomes_quarantine_test() {
  let quarantined = fn(result) {
    case result {
      Error(warden.RefreshQuarantined(warden.ProviderOutcomeUnknown)) ->
        "provider"
      Error(warden.RefreshQuarantined(warden.ResponseRejected(problem))) ->
        string.inspect(problem)
      other -> "unexpected " <> string.inspect(other)
    }
  }
  let cases = [
    #(support.Delay(1500), "provider"),
    #(support.Status(503, "temporarily_unavailable"), "provider"),
    #(support.Close, "provider"),
    #(support.MalformedJson, "RefreshResponseMalformed"),
    // Tokens Warden cannot use as Bearer tokens, or a negative lifetime.
    #(support.TokenField("token_type", "DPoP"), "RefreshResponseMalformed"),
    #(support.TokenIntField("expires_in", -5), "RefreshResponseMalformed"),
    // An error code Warden does not recognise may follow processing of the
    // grant; the token it sent is never sent again.
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
    // A quarantined generation never dispatches again, and its reason is
    // kept in custody.
    assert #(c.0, quarantined(second)) == #(c.0, c.1)
    let assert Error(error) = second
    assert warden.session_error_action(error) == warden.Reauthenticate
  })
}

pub fn definite_rejection_revokes_or_releases_test() {
  let #(first, second) = refresh_with(support.Status(400, "invalid_grant"))
  assert first == Error(warden.RefreshRevoked)
  assert second == Error(warden.RefreshRevoked)
  // A rejection that does not concern the grant releases the generation.
  let #(first, second) = refresh_with(support.Status(401, "invalid_client"))
  assert first == Error(warden.RefreshRejected(warden.InvalidClient))
  let assert Ok(_) = second
}

pub fn bearer_token_type_is_case_insensitive_test() {
  let #(first, _) = refresh_with(support.TokenField("token_type", "bearer"))
  let assert Ok(_) = first
}

pub fn proven_no_send_releases_the_generation_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  support.provider_stop(provider)
  let not_sent =
    Error(
      warden.RefreshNotSent(warden.TransportFailure(
        evidence: warden.NotSent,
        reason: warden.ConnectionRefused,
      )),
    )
  assert warden.refresh(client, session) == not_sent
  // Released, not quarantined: another attempt is admitted.
  assert warden.refresh(client, session) == not_sent
  warden.stop(client)
}

fn durable_client(
  provider: support.Provider,
) -> #(warden.Client, faults.Control) {
  let #(custody, control) = faults.memory()
  let client =
    start(
      settings(provider)
      |> config.with_store_timeout(duration.milliseconds(200))
      |> config.with_custody_store(custody)
      |> config.with_sealing_key(faults.sealing_key()),
    )
  #(client, control)
}

pub fn lost_publication_acknowledgement_recovers_without_provider_test() {
  let provider = support.provider_start(support.Standard)
  let #(client, control) = durable_client(provider)
  let session = logged_in(provider, client)
  // Writes during the refresh: the reservation, then the publication.
  faults.lose_ack_of(control, 2)
  let assert Error(warden.RefreshUnconfirmed(recovery) as error) =
    warden.refresh(client, session)
  assert warden.session_error_action(error) == warden.Recover
  let requests = support.token_requests(provider)
  let assert Ok(recovered) = warden.recover_refresh(client, recovery)
  let assert Ok(again) = warden.recover_refresh(client, recovery)
  assert token(recovered) == token(again)
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
  assert warden.refresh(b, session) == Error(warden.SessionForeign)
  assert warden.access_token(b, session) == Error(warden.SessionForeign)
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
  let now = support.now_seconds()
  let assert Ok(token) = warden.client_credentials(client, ["api"])
  assert warden.access_token_value(token.access_token) != ""
  let assert Some(expires_at) = token.expires_at
  let #(expires, _) = timestamp.to_unix_seconds_and_nanoseconds(expires_at)
  assert expires >= now + 59 && expires <= now + 61
  let assert Error(warden.ClientCredentialsInvalidScope(_)) =
    warden.client_credentials(client, ["a b"])
  warden.stop(client)
  let public =
    start(
      config.new(
        issuer: support.provider_issuer(provider),
        client_id: "warden-rp",
        redirect_uri: "https://app.example/callback",
        authentication: config.PublicClient,
      )
      |> config.with_trust(config.TrustAnchorsPem(support.ca_pem()))
      |> config.with_destinations(config.AllowLoopbackForTesting)
      |> config.with_signing_algorithms([config.Rs256]),
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
  assert warden.decode_token_claims(
      info,
      decode.at(["department"], decode.string),
    )
    == Ok("platform")
  let assert Ok(warden.InactiveToken) = warden.introspect(client, "unknown")
  // An oversized token is refused locally.
  assert warden.introspect(client, string.repeat("t", 8193))
    == Error(warden.IntrospectionTokenTooLarge)
  support.provider_stop(provider)
  let assert Error(warden.IntrospectionFailed(warden.TransportFailure(
    evidence: warden.NotSent,
    ..,
  ))) = warden.introspect(client, "active-token")
  warden.stop(client)
}

/// An active answer whose `exp` has passed is inactive, with no
/// clock tolerance. Both sides use one fixed expiry, independent of
/// startup latency and the wall-clock second in which a request arrives.
pub fn introspection_checks_exp_strictly_test() {
  let provider = support.provider_start(support.Standard)
  let expires_at = 2_000_000_000
  support.set_introspection_expiry(provider, expires_at)
  let clock = support.clock_new(expires_at)
  let client = start(settings(provider) |> with_clock(clock))
  assert warden.introspect(client, "active-token") == Ok(warden.InactiveToken)
  support.clock_set(clock, expires_at - 1)
  let assert Ok(warden.ActiveToken(_)) =
    warden.introspect(client, "active-token")
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn logout_removes_custody_then_redirects_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let assert Ok(warden.LoggedOut(
    provider_logout: warden.RedirectToProvider(redirect) as provider_logout,
    // The scripted provider advertises no revocation endpoint.
    revocation: warden.RevocationUnsupported,
  )) =
    warden.logout(
      client,
      session,
      warden.LogoutOptions(
        ..warden.default_logout(),
        post_logout_redirect_uri: Some("https://app.example/logged-out"),
        state: Some("logout-state"),
      ),
    )
  let url = warden.logout_url(redirect)
  assert string.starts_with(
    url,
    support.provider_issuer(provider) <> "/logout?",
  )
  assert string.contains(url, "id_token_hint=")
  assert string.contains(url, "post_logout_redirect_uri=")
  assert string.contains(url, "state=logout-state")
  // The redirect carries the ID token, so it does not print.
  assert !string.contains(string.inspect(provider_logout), "id_token_hint")
  assert warden.restore_session(client, warden.session_reference(session))
    == Error(warden.SessionNotFound)
  assert warden.refresh(client, session) == Error(warden.SessionNotFound)
  let assert Error(warden.InvalidPostLogoutRedirect) =
    warden.logout(
      client,
      logged_in(provider, client),
      warden.LogoutOptions(
        ..warden.default_logout(),
        post_logout_redirect_uri: Some("javascript:alert(1)"),
      ),
    )
  warden.stop(client)
  support.provider_stop(provider)
}

/// Request A holds the session value from before request B refreshed
/// it. A's logout still ends the session; a second logout reports that no
/// session existed.
pub fn logout_with_an_older_session_value_ends_the_session_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let assert Ok(refreshed) = warden.refresh(client, session)
  let assert Ok(warden.LoggedOut(
    provider_logout: warden.RedirectToProvider(redirect),
    ..,
  )) = warden.logout(client, session, warden.default_logout())
  assert string.contains(warden.logout_url(redirect), "id_token_hint=")
  assert warden.restore_session(client, warden.session_reference(session))
    == Error(warden.SessionNotFound)
  assert warden.refresh(client, refreshed.session)
    == Error(warden.SessionNotFound)
  assert warden.logout(client, refreshed.session, warden.default_logout())
    == Error(warden.LogoutSession(warden.SessionNotFound))
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn logout_without_end_session_endpoint_is_explicit_test() {
  let provider = support.provider_start(support.NoEndSession)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let assert Ok(warden.LoggedOut(
    provider_logout: warden.NoEndSessionEndpoint,
    revocation: warden.RevocationSkipped,
  )) =
    warden.logout(
      client,
      session,
      warden.LogoutOptions(
        ..warden.default_logout(),
        revocation: warden.SkipRevocation,
      ),
    )
  assert warden.restore_session(client, warden.session_reference(session))
    == Error(warden.SessionNotFound)
  warden.stop(client)
  support.provider_stop(provider)
}

/// The in-memory custody restarts empty: the session is reported lost (not
/// merely missing), and refresh never reaches the provider.
pub fn custody_loss_is_reported_as_lost_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let requests = support.token_requests(provider)
  let assert Some(name) = client.names.memory_custody
  let assert Ok(pid) = process.named(name)
  process.kill(pid)
  process.sleep(100)
  assert warden.refresh(client, session) == Error(warden.SessionLost)
  assert warden.restore_session(client, warden.session_reference(session))
    == Error(warden.SessionLost)
  assert warden.restore_session(client, "never-issued")
    == Error(warden.SessionNotFound)
  assert support.token_requests(provider) == requests
  warden.stop(client)
  support.provider_stop(provider)
}

/// OIDC Core §12.2 permits a refresh response without an ID token; the
/// established identity is kept.
pub fn refresh_without_id_token_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  support.script(
    provider,
    support.Refresh(refresh_token_of(provider)),
    support.OmitIdToken,
  )
  let assert Ok(refreshed) = warden.refresh(client, session)
  assert warden.identity_key(warden.session_identity(refreshed.session))
    == warden.identity_key(warden.session_identity(session))
  let assert Ok(_) = warden.refresh(client, refreshed.session)
  warden.stop(client)
  support.provider_stop(provider)
}

/// A refresher that dies mid-request may already have reached the provider.
/// Its lease runs out and the generation is quarantined, never released.
pub fn an_expired_refresh_lease_quarantines_the_generation_test() {
  let provider = support.provider_start(support.Standard)
  let base = support.now_seconds()
  let clock = support.clock_new(base)
  let client =
    start(
      settings(provider)
      |> config.with_request_timeout(duration.milliseconds(500))
      |> config.with_store_timeout(duration.milliseconds(200))
      |> config.with_refresh_wait(duration.milliseconds(100))
      |> with_clock(clock),
    )
  let session = logged_in(provider, client)
  support.script(
    provider,
    support.Refresh(refresh_token_of(provider)),
    support.Delay(3000),
  )
  let dispatcher =
    process.spawn_unlinked(fn() { warden.refresh(client, session) })
  process.sleep(200)
  process.kill(dispatcher)
  // Within the lease, another request waits and gives up.
  assert warden.refresh(client, session) == Error(warden.RefreshWaitTimedOut)
  // Past the lease (request + 2 store timeouts + 1 s), it is quarantined.
  support.clock_set(clock, base + 3)
  assert warden.refresh(client, session)
    == Error(warden.RefreshQuarantined(warden.RefresherLost))
  assert warden.refresh(client, session)
    == Error(warden.RefreshQuarantined(warden.RefresherLost))
  warden.stop(client)
  support.provider_stop(provider)
}

/// A request may return `RefreshUnconfirmed` and exit; another process
/// recovers the publication with the value it handed over.
pub fn publication_recovery_survives_the_dispatcher_test() {
  let provider = support.provider_start(support.Standard)
  let #(client, control) = durable_client(provider)
  let session = logged_in(provider, client)
  faults.lose_ack_of(control, 2)
  let handed_over = process.new_subject()
  process.spawn_unlinked(fn() {
    let assert Error(warden.RefreshUnconfirmed(recovery)) =
      warden.refresh(client, session)
    process.send(handed_over, recovery)
  })
  let assert Ok(recovery) = process.receive(handed_over, 2000)
  let assert Ok(_) = warden.recover_refresh(client, recovery)
  warden.stop(client)
  support.provider_stop(provider)
}

/// An idle session ends in custody: it can no longer be restored, and its
/// tokens are gone.
pub fn idle_sessions_end_test() {
  let provider = support.provider_start(support.Standard)
  let clock = support.clock_new(support.now_seconds())
  let client =
    start(
      settings(provider)
      |> config.with_session_lifetime(
        absolute: duration.minutes(10),
        idle: duration.seconds(60),
      )
      |> with_clock(clock),
    )
  let session = logged_in(provider, client)
  let reference = warden.session_reference(session)
  let assert Ok(_) = warden.restore_session(client, reference)
  support.clock_set(clock, support.clock_read(clock) + 61)
  assert warden.restore_session(client, reference)
    == Error(warden.SessionNotFound)
  warden.stop(client)
  support.provider_stop(provider)
}

/// Use restarts the idle period.
pub fn use_restarts_the_idle_period_test() {
  let provider = support.provider_start(support.Standard)
  let base = support.now_seconds()
  let clock = support.clock_new(base)
  let client =
    start(
      settings(provider)
      |> config.with_session_lifetime(
        absolute: duration.minutes(10),
        idle: duration.seconds(60),
      )
      |> with_clock(clock),
    )
  let session = logged_in(provider, client)
  let reference = warden.session_reference(session)
  list.each([40, 80, 120, 160], fn(t) {
    support.clock_set(clock, base + t)
    let assert Ok(_) = warden.restore_session(client, reference)
  })
  support.clock_set(clock, base + 230)
  assert warden.restore_session(client, reference)
    == Error(warden.SessionNotFound)
  warden.stop(client)
  support.provider_stop(provider)
}

/// A provider that closes the connection without answering: the request may
/// have been sent, and the public reason is `ReceiveFailed`.
pub fn a_closed_connection_reports_receive_failed_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  support.script(provider, support.Userinfo, support.Close)
  assert warden.userinfo(client, session)
    == Error(
      warden.UserinfoFailed(warden.TransportFailure(
        evidence: warden.MaybeSent,
        reason: warden.ReceiveFailed,
      )),
    )
  let _ = browser
  let _ = None
  warden.stop(client)
  support.provider_stop(provider)
}

/// A refresh that decides nothing leaves an unexpired token in use: the
/// provider is down, the token expires in 10 s (inside the margin), and
/// `access_token` still returns it; `refresh` reports the failure.
pub fn an_undecided_refresh_keeps_the_unexpired_token_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  support.script(
    provider,
    support.Refresh(refresh_token_of(provider)),
    support.TokenIntField("expires_in", 10),
  )
  let assert Ok(short) = warden.refresh(client, session)
  support.provider_stop(provider)
  let assert Ok(same) = warden.access_token(client, short.session)
  assert token(same) == token(short)
  let assert Error(warden.RefreshNotSent(_)) =
    warden.refresh(client, short.session)
  warden.stop(client)
}
