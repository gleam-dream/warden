//// Login orchestration against the scripted in-process provider: atomic
//// consumption under contention, clock sampling inside the store's critical
//// section, store loss, exchange outcomes, identity rejection and custody
//// recovery. Every provider request crosses Warden's real TLS transport.

import gleam/dict
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleam/uri
import warden
import warden/config
import warden/internal/custody_store
import warden/internal/transaction_store
import warden/internal/transport
import warden_test_support as support

pub fn settings(provider: support.Provider) -> config.Settings {
  config.new(
    issuer: support.provider_issuer(provider),
    client_id: "warden-rp",
    redirect_uri: "https://app.example/callback",
    authentication: config.ClientSecretBasic(config.secret("sentinel-secret")),
  )
  |> config.with_scopes(["email"])
  |> config.with_trust(config.TrustAnchorsPem(support.ca_pem()))
  |> config.with_destinations(config.AllowLoopbackForTesting)
  |> config.with_signing_algorithms([config.Rs256])
}

pub fn start(settings: config.Settings) -> warden.Client {
  let assert Ok(validated) = config.validate(settings)
  let assert Ok(client) = warden.start(validated)
  client
}

pub fn param(url: String, name: String) -> String {
  let assert Ok(#(_, query)) = string.split_once(url, "?")
  let assert Ok(params) = uri.parse_query(query)
  let assert Ok(value) = list.key_find(params, name)
  value
}

/// Act as the browser and provider front channel: register a code for the
/// transaction's nonce and build the callback query.
pub fn authorize(
  provider: support.Provider,
  redirect: warden.LoginRedirect,
  code: String,
) -> String {
  support.issue_code(provider, code, param(redirect.url, "nonce"))
  uri.query_to_string([
    #("code", code),
    #("state", param(redirect.url, "state")),
    #("iss", support.provider_issuer(provider)),
  ])
}

pub fn logged_in(
  provider: support.Provider,
  client: warden.Client,
) -> warden.Session {
  let assert Ok(redirect) =
    warden.begin_login(client, None, warden.default_login())
  let query =
    authorize(provider, redirect, "code-" <> param(redirect.url, "state"))
  let assert Ok(warden.LoginCompleted(session)) =
    warden.complete_login(
      client,
      warden.QueryCallback(query),
      Some(redirect.browser_binding),
    )
  session
}

type Department {
  Department(name: String)
}

pub fn login_issues_identity_with_custom_claims_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let identity = warden.session_identity(session)
  assert warden.subject(identity) == "subject-1"
  assert warden.issuer(identity) == support.provider_issuer(provider)
  let decoder = {
    use name <- decode.field("department", decode.string)
    decode.success(Department(name))
  }
  assert warden.decode_claims(identity, decoder) == Ok(Department("platform"))
  assert support.token_requests(provider) == 1
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn authorization_url_carries_s256_and_fresh_material_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let assert Ok(a) = warden.begin_login(client, None, warden.default_login())
  let assert Ok(b) = warden.begin_login(client, None, warden.default_login())
  assert param(a.url, "code_challenge_method") == "S256"
  assert string.length(param(a.url, "code_challenge")) == 43
  assert string.length(param(a.url, "state")) == 43
  assert string.length(param(a.url, "nonce")) == 43
  assert param(a.url, "state") != param(b.url, "state")
  assert param(a.url, "nonce") != param(b.url, "nonce")
  assert param(a.url, "code_challenge") != param(b.url, "code_challenge")
  assert param(a.url, "scope") == "openid email"
  assert a.browser_binding != b.browser_binding
  // The verifier never appears in the URL.
  assert !string.contains(a.url, "code_verifier")
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn racing_callbacks_consume_once_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let assert Ok(redirect) =
    warden.begin_login(client, None, warden.default_login())
  let query = authorize(provider, redirect, "race-code")
  let attempt = fn() {
    warden.complete_login(
      client,
      warden.QueryCallback(query),
      Some(redirect.browser_binding),
    )
  }
  let results = support.spawn_collect(list.repeat(attempt, 16), 30_000)
  let completed =
    list.count(results, fn(r) {
      case r {
        Ok(warden.LoginCompleted(_)) -> True
        _ -> False
      }
    })
  assert completed == 1
  assert list.count(results, fn(r) { r == Error(warden.LoginReplayed) }) == 15
  assert support.token_requests(provider) == 1
  warden.stop(client)
  support.provider_stop(provider)
}

/// The consume request is queued while the store is held; the clock moves to
/// exactly `expires_at` before release. The store samples the clock inside
/// its critical section, so the login expires and no token request is sent.
pub fn clock_is_sampled_inside_the_critical_section_test() {
  let provider = support.provider_start(support.Standard)
  let base = support.now_seconds()
  let clock = support.clock_new(base)
  let assert Ok(validated) =
    config.validate(settings(provider) |> config.with_login_lifetime(60))
  let assert Ok(client) =
    warden.start_with_clock(validated, fn() { support.clock_read(clock) })
  let assert Ok(redirect) =
    warden.begin_login(client, None, warden.default_login())
  let query = authorize(provider, redirect, "held-code")
  support.clock_set(clock, base + 59)
  let assert Ok(release) =
    transaction_store.hold(warden.transaction_store(client))
  let result_subject = process.new_subject()
  process.spawn(fn() {
    process.send(
      result_subject,
      warden.complete_login(
        client,
        warden.QueryCallback(query),
        Some(redirect.browser_binding),
      ),
    )
  })
  process.sleep(100)
  support.clock_set(clock, base + 60)
  process.send(release, Nil)
  let assert Ok(result) = process.receive(result_subject, 5000)
  assert result == Error(warden.LoginExpired)
  assert support.token_requests(provider) == 0
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn one_second_before_expiry_completes_test() {
  let provider = support.provider_start(support.Standard)
  let base = support.now_seconds()
  let clock = support.clock_new(base)
  let assert Ok(validated) =
    config.validate(settings(provider) |> config.with_login_lifetime(60))
  let assert Ok(client) =
    warden.start_with_clock(validated, fn() { support.clock_read(clock) })
  let assert Ok(redirect) =
    warden.begin_login(client, None, warden.default_login())
  let query = authorize(provider, redirect, "edge-code")
  support.clock_set(clock, base + 59)
  let assert Ok(warden.LoginCompleted(_)) =
    warden.complete_login(
      client,
      warden.QueryCallback(query),
      Some(redirect.browser_binding),
    )
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn store_loss_never_authorises_exchange_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let assert Ok(redirect) =
    warden.begin_login(client, None, warden.default_login())
  let query = authorize(provider, redirect, "lost-code")
  // The store restarts empty under supervision: the login is gone.
  let assert Ok(release) =
    transaction_store.hold(warden.transaction_store(client))
  let assert Ok(pid) =
    process.subject_owner(warden.transaction_store(client).subject)
  process.kill(pid)
  let _ = release
  process.sleep(50)
  let assert Error(warden.CallbackRejected(warden.UnknownState)) =
    warden.complete_login(
      client,
      warden.QueryCallback(query),
      Some(redirect.browser_binding),
    )
  assert support.token_requests(provider) == 0
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn store_timeout_is_typed_and_sends_nothing_test() {
  let provider = support.provider_start(support.Standard)
  let settings = config.Settings(..settings(provider), store_timeout_ms: 200)
  let client = start(settings)
  let assert Ok(redirect) =
    warden.begin_login(client, None, warden.default_login())
  let query = authorize(provider, redirect, "slow-code")
  let assert Ok(release) =
    transaction_store.hold(warden.transaction_store(client))
  let assert Error(warden.TransactionStoreUnavailable) =
    warden.complete_login(
      client,
      warden.QueryCallback(query),
      Some(redirect.browser_binding),
    )
  process.send(release, Nil)
  assert support.token_requests(provider) == 0
  warden.stop(client)
  support.provider_stop(provider)
}

fn exchange_outcome(
  behaviour: support.Behaviour,
  settings_fn: fn(config.Settings) -> config.Settings,
) -> #(Result(warden.LoginCompletion, warden.LoginError), Int) {
  let provider = support.provider_start(support.Standard)
  let client = start(settings_fn(settings(provider)))
  let assert Ok(redirect) =
    warden.begin_login(client, None, warden.default_login())
  let code = "code-" <> param(redirect.url, "state")
  let query = authorize(provider, redirect, code)
  support.script(provider, support.Code(code), behaviour)
  let result =
    warden.complete_login(
      client,
      warden.QueryCallback(query),
      Some(redirect.browser_binding),
    )
  // The login is consumed whatever the outcome: a retry is a replay and
  // sends nothing.
  let assert Error(warden.LoginReplayed) =
    warden.complete_login(
      client,
      warden.QueryCallback(query),
      Some(redirect.browser_binding),
    )
  let requests = support.token_requests(provider)
  warden.stop(client)
  support.provider_stop(provider)
  #(result, requests)
}

fn same(s: config.Settings) -> config.Settings {
  s
}

pub fn exchange_outcomes_are_classified_test() {
  let short = fn(s: config.Settings) {
    config.with_transport(
      s,
      config.Transport(..s.transport, request_timeout_ms: 400),
    )
  }
  let cases = [
    #(
      support.Status(400, "invalid_grant"),
      same,
      Error(warden.ExchangeRejected(warden.InvalidGrant)),
    ),
    #(
      support.Status(401, "invalid_client"),
      same,
      Error(warden.ExchangeRejected(warden.InvalidClient)),
    ),
    #(
      support.Status(500, "server_error"),
      same,
      Error(warden.ExchangeOutcomeUnknown),
    ),
    #(
      support.Status(400, "not-a-known-code"),
      same,
      Error(warden.ExchangeRejected(warden.OtherOAuthError)),
    ),
    #(support.Delay(1500), short, Error(warden.ExchangeOutcomeUnknown)),
    #(support.Close, same, Error(warden.ExchangeOutcomeUnknown)),
    #(support.MalformedJson, same, Error(warden.ExchangeOutcomeUnknown)),
    #(
      support.OmitIdToken,
      same,
      Error(warden.IdentityRejected(warden.MissingIdToken)),
    ),
    #(
      support.IdToken("wrong_aud"),
      same,
      Error(warden.IdentityRejected(warden.IdTokenAudienceMismatch)),
    ),
    #(
      support.IdToken("extra_aud"),
      same,
      Error(warden.IdentityRejected(warden.IdTokenAudienceMismatch)),
    ),
    #(
      support.IdToken("wrong_azp"),
      same,
      Error(warden.IdentityRejected(warden.AuthorizedPartyMismatch)),
    ),
    #(
      support.IdToken("wrong_nonce"),
      same,
      Error(warden.IdentityRejected(warden.NonceMismatch)),
    ),
    #(
      support.IdToken("expired"),
      same,
      Error(warden.IdentityRejected(warden.IdTokenExpired)),
    ),
    #(
      support.IdToken("unknown_kid"),
      same,
      Error(warden.IdentityRejected(warden.UnknownSigningKey)),
    ),
  ]
  list.each(cases, fn(c) {
    let #(result, requests) = exchange_outcome(c.0, c.1)
    assert #(c.0, result) == #(c.0, c.2)
    assert requests == 1
  })
}

pub fn provider_down_before_exchange_is_proven_not_sent_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let assert Ok(redirect) =
    warden.begin_login(client, None, warden.default_login())
  let query = authorize(provider, redirect, "down-code")
  support.provider_stop(provider)
  let assert Error(warden.ProviderUnavailableBeforeExchange(warden.TransportFailure(
    sent: False,
    reason: warden.ConnectionRefused,
  ))) =
    warden.complete_login(
      client,
      warden.QueryCallback(query),
      Some(redirect.browser_binding),
    )
  // Consumed all the same: the initial contract requires a new login.
  let assert Error(warden.LoginReplayed) =
    warden.complete_login(
      client,
      warden.QueryCallback(query),
      Some(redirect.browser_binding),
    )
  warden.stop(client)
}

pub fn lost_custody_acknowledgement_recovers_without_exchange_test() {
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
  let query = authorize(provider, redirect, "custody-code")
  let assert Ok(warden.LoginRecoveryRequired(recovery)) =
    warden.complete_login(
      client,
      warden.QueryCallback(query),
      Some(redirect.browser_binding),
    )
  process.sleep(600)
  let assert Ok(Nil) =
    custody_store.delay_replies(
      warden.custody_owner(client),
      custody_store.DelayNothing,
      0,
    )
  let assert Ok(warden.CustodyRecovered(session)) =
    warden.recover_custody(client, recovery)
  // Idempotent: the same command yields the same installed session.
  let assert Ok(warden.CustodyRecovered(again)) =
    warden.recover_custody(client, recovery)
  assert warden.session_reference(session) == warden.session_reference(again)
  assert warden.session_revision(session) == 1
  assert support.token_requests(provider) == 1
  // After logout the recovery cannot resurrect the session (finding F5).
  let assert Ok(_) =
    warden.logout(
      client,
      session,
      warden.LogoutOptions(post_logout_redirect_uri: None, state: None),
    )
  assert warden.recover_custody(client, recovery) == Error(warden.RecoveryEnded)
  // A different client configuration cannot use the recovery.
  let other_provider = support.provider_start(support.Standard)
  let other = start(settings(other_provider))
  let assert Error(warden.RecoveryOwnerMismatch) =
    warden.recover_custody(other, recovery)
  warden.stop(other)
  support.provider_stop(other_provider)
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn max_age_requires_recent_authentication_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let options = fn(age) {
    warden.LoginOptions(..warden.default_login(), max_age: Some(age))
  }
  let assert Ok(strict) = warden.begin_login(client, None, options(1))
  assert param(strict.url, "max_age") == "1"
  let query = authorize(provider, strict, "strict-code")
  let assert Error(warden.IdentityRejected(warden.AuthenticationTooOld)) =
    warden.complete_login(
      client,
      warden.QueryCallback(query),
      Some(strict.browser_binding),
    )
  let assert Ok(relaxed) = warden.begin_login(client, None, options(300))
  let query = authorize(provider, relaxed, "relaxed-code")
  let assert Ok(warden.LoginCompleted(_)) =
    warden.complete_login(
      client,
      warden.QueryCallback(query),
      Some(relaxed.browser_binding),
    )
  warden.stop(client)
  support.provider_stop(provider)
}

/// An `auth_time` in the future is not a recent authentication (J9).
pub fn future_authentication_time_fails_max_age_test() {
  let provider = support.provider_start(support.Standard)
  support.set_int_claims(
    provider,
    dict.from_list([#("auth_time", support.now_seconds() + 3600)]),
  )
  let client = start(settings(provider))
  let assert Ok(redirect) =
    warden.begin_login(
      client,
      None,
      warden.LoginOptions(..warden.default_login(), max_age: Some(300)),
    )
  let query = authorize(provider, redirect, "future-code")
  let assert Error(warden.IdentityRejected(warden.AuthenticationTooOld)) =
    warden.complete_login(
      client,
      warden.QueryCallback(query),
      Some(redirect.browser_binding),
    )
  warden.stop(client)
  support.provider_stop(provider)
}

/// Pending-login lifetimes run on the monotonic clock, so a wall-clock step
/// (NTP) neither extends nor cuts them short (review finding F9).
pub fn login_lifetime_follows_the_monotonic_clock_test() {
  let provider = support.provider_start(support.Standard)
  let monotonic = support.clock_new(1000)
  let assert Ok(validated) = config.validate(settings(provider))
  let assert Ok(client) =
    warden.start_with_clocks(
      validated,
      wall: support.now_seconds,
      monotonic: fn() { support.clock_read(monotonic) },
    )
  let assert Ok(redirect) =
    warden.begin_login(client, None, warden.default_login())
  let query = authorize(provider, redirect, "monotonic-code")
  // Ten minutes pass on the monotonic clock; the wall clock does not move.
  support.clock_set(monotonic, 1000 + 601)
  assert warden.complete_login(
      client,
      warden.QueryCallback(query),
      Some(redirect.browser_binding),
    )
    == Error(warden.LoginExpired)
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn login_options_are_validated_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let with = fn(extra) {
    warden.begin_login(
      client,
      None,
      warden.LoginOptions(..warden.default_login(), extra_parameters: extra),
    )
  }
  let assert Error(warden.InvalidLoginOption(warden.ReservedParameter("state"))) =
    with([#("state", "x")])
  let assert Error(warden.InvalidLoginOption(warden.ReservedParameter(
    "Redirect_URI",
  ))) = with([#("Redirect_URI", "https://evil.example")])
  let assert Error(warden.InvalidLoginOption(warden.InvalidParameterValue(_))) =
    with([#("x", "a\nb")])
  let assert Ok(redirect) = with([#("resource", "https://api.example")])
  assert param(redirect.url, "resource") == "https://api.example"
  let assert Error(warden.InvalidLoginOption(warden.InvalidOptionScope(_))) =
    warden.begin_login(
      client,
      None,
      warden.LoginOptions(..warden.default_login(), scopes: ["bad scope"]),
    )
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn incompatible_providers_are_rejected_at_startup_test() {
  let cases = [
    #(support.NoS256, Error(warden.ProviderIncompatible([warden.NoS256]))),
    #(
      support.RequiresPar,
      Error(warden.ProviderIncompatible([warden.RequiresPushedAuthorization])),
    ),
    #(
      support.Hs256Only,
      Error(warden.ProviderIncompatible([warden.NoCommonSigningAlgorithm])),
    ),
    #(support.WrongIssuer, Error(warden.DiscoveryFailed(warden.IssuerMismatch))),
  ]
  list.each(cases, fn(c) {
    let provider = support.provider_start(c.0)
    let assert Ok(validated) = config.validate(settings(provider))
    let result = warden.start(validated) |> result_error
    assert result == c.1
    support.provider_stop(provider)
  })
}

/// D7: `AssumeS256WhenUnadvertised` accepts only a provider that omits
/// `code_challenge_methods_supported`; Warden still sends its S256 challenge.
pub fn unadvertised_pkce_is_accepted_only_by_explicit_policy_test() {
  let assume = fn(provider) {
    settings(provider)
    |> config.with_pkce_advertisement(config.AssumeS256WhenUnadvertised)
  }
  let provider = support.provider_start(support.UnadvertisedPkce)
  let assert Ok(strict) = config.validate(settings(provider))
  assert warden.start(strict) |> result_error
    == Error(warden.ProviderIncompatible([warden.NoS256]))
  let assert Ok(assumed) = config.validate(assume(provider))
  assert config.pkce_advertisement(assumed) == config.AssumeS256WhenUnadvertised
  let assert Ok(client) = warden.start(assumed)
  let assert Ok(redirect) =
    warden.begin_login(client, None, warden.default_login())
  assert param(redirect.url, "code_challenge_method") == "S256"
  assert string.length(param(redirect.url, "code_challenge")) == 43
  warden.stop(client)
  support.provider_stop(provider)

  // Advertising methods without S256 is refused under either policy, and
  // so is an explicit empty list: only an omitted field is "unadvertised".
  list.each([support.NoS256, support.EmptyPkceMethods], fn(variant) {
    let provider = support.provider_start(variant)
    let assert Ok(assumed) = config.validate(assume(provider))
    assert warden.start(assumed) |> result_error
      == Error(warden.ProviderIncompatible([warden.NoS256]))
    support.provider_stop(provider)
  })
}

/// An authorization endpoint may carry its own query, as Azure AD B2C's
/// policy parameter does (review finding J6).
pub fn authorization_endpoint_query_is_preserved_test() {
  let provider = support.provider_start(support.QueryInAuthorizationEndpoint)
  let client = start(settings(provider))
  let assert Ok(redirect) =
    warden.begin_login(client, None, warden.default_login())
  assert param(redirect.url, "p") == "b2c_1_signin"
  assert string.length(param(redirect.url, "code_challenge")) == 43
  warden.stop(client)
  support.provider_stop(provider)
}

/// The browser is sent to the end-session endpoint with an ID-token hint,
/// so it must be HTTPS like the authorization endpoint (J11).
pub fn insecure_end_session_endpoint_is_refused_test() {
  let provider = support.provider_start(support.InsecureEndSession)
  let assert Ok(validated) = config.validate(settings(provider))
  assert warden.start(validated) |> result_error
    == Error(warden.ProviderIncompatible([warden.InsecureEndSessionEndpoint]))
  support.provider_stop(provider)
}

/// `startup_timeout_ms` bounds discovery and the first key load together.
pub fn startup_is_bounded_by_startup_timeout_test() {
  // Answers every request after 3 s.
  let server = support.server_start("localhost", support.Slow)
  let settings =
    config.new(
      issuer: support.server_url(server, ""),
      client_id: "warden-rp",
      redirect_uri: "https://app.example/callback",
      authentication: config.ClientSecretBasic(config.secret("sentinel-secret")),
    )
    |> config.with_trust(config.TrustAnchorsPem(support.ca_pem()))
    |> config.with_destinations(config.AllowLoopbackForTesting)
  let assert Ok(validated) =
    config.validate(config.Settings(..settings, startup_timeout_ms: 300))
  let started = transport.monotonic_ms()
  assert warden.start(validated) |> result_error
    == Error(warden.StartupTimedOut)
  assert transport.monotonic_ms() - started < 2000
  support.server_stop(server)
}

fn result_error(
  r: Result(warden.Client, warden.StartError),
) -> Result(Nil, warden.StartError) {
  case r {
    Ok(client) -> {
      warden.stop(client)
      Ok(Nil)
    }
    Error(e) -> Error(e)
  }
}

pub fn loopback_provider_is_rejected_by_default_policy_test() {
  let provider = support.provider_start(support.Standard)
  let assert Ok(validated) =
    config.validate(
      settings(provider) |> config.with_destinations(config.PublicInternetOnly),
    )
  let assert Error(warden.DiscoveryFailed(warden.TransportFailure(
    sent: False,
    reason: warden.DestinationRejected,
  ))) = warden.start(validated)
  support.provider_stop(provider)
}

pub fn missing_issuer_parameter_follows_policy_test() {
  // The provider does not advertise RFC 9207: absence is accepted by the
  // default policy and rejected by AlwaysRequireIssuer.
  let provider = support.provider_start(support.NoIssParameter)
  let client = start(settings(provider))
  let assert Ok(redirect) =
    warden.begin_login(client, None, warden.default_login())
  support.issue_code(provider, "no-iss", param(redirect.url, "nonce"))
  let query =
    uri.query_to_string([
      #("code", "no-iss"),
      #("state", param(redirect.url, "state")),
    ])
  let assert Ok(warden.LoginCompleted(_)) =
    warden.complete_login(
      client,
      warden.QueryCallback(query),
      Some(redirect.browser_binding),
    )
  warden.stop(client)
  let strict =
    start(
      settings(provider)
      |> config.with_issuer_parameter(config.AlwaysRequireIssuer),
    )
  let assert Ok(redirect) =
    warden.begin_login(strict, None, warden.default_login())
  let query =
    uri.query_to_string([
      #("code", "x"),
      #("state", param(redirect.url, "state")),
    ])
  let assert Error(warden.CallbackRejected(warden.CallbackIssuerMissing)) =
    warden.complete_login(
      strict,
      warden.QueryCallback(query),
      Some(redirect.browser_binding),
    )
  warden.stop(strict)
  support.provider_stop(provider)
}

pub fn denial_codes_are_closed_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let deny = fn(code) {
    let assert Ok(redirect) =
      warden.begin_login(client, None, warden.default_login())
    warden.complete_login(
      client,
      warden.QueryCallback(
        uri.query_to_string([
          #("error", code),
          #("error_description", "secret-looking description"),
          #("state", param(redirect.url, "state")),
          #("iss", support.provider_issuer(provider)),
        ]),
      ),
      Some(redirect.browser_binding),
    )
  }
  assert deny("access_denied")
    == Error(warden.ProviderDenied(warden.AccessDenied))
  assert deny("consent_required")
    == Error(warden.ProviderDenied(warden.ConsentRequired))
  assert deny("made_up") == Error(warden.ProviderDenied(warden.OtherDenial))
  assert support.token_requests(provider) == 0
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn form_post_mode_rejects_query_callbacks_test() {
  let provider = support.provider_start(support.Standard)
  let client =
    start(settings(provider) |> config.with_response_mode(config.FormPost))
  let assert Ok(redirect) =
    warden.begin_login(client, None, warden.default_login())
  assert param(redirect.url, "response_mode") == "form_post"
  let body = authorize(provider, redirect, "form-code")
  let assert Error(warden.CallbackMalformed(warden.UnexpectedResponseMode)) =
    warden.complete_login(
      client,
      warden.QueryCallback(body),
      Some(redirect.browser_binding),
    )
  let assert Ok(warden.LoginCompleted(_)) =
    warden.complete_login(
      client,
      warden.FormPostCallback(string.replace(body, "%20", "+")),
      Some(redirect.browser_binding),
    )
  warden.stop(client)
  support.provider_stop(provider)
}

pub fn unused_dict_import_guard_test() {
  // Keeps the dict import exercised for set_claims-based tests below.
  assert dict.size(dict.new()) == 0
}
