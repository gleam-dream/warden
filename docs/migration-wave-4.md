# Wave 4 migration

Wave 4 is Warden's release API redesign (WARDEN-R1 to R11, the
resource-server role, and the wave 1 to 3 follow-ups). Every public module
changes. In short:

- configuration is an opaque `Config` with `Duration` setters, and
  `warden.new` validates it;
- the lifecycle is `new`, then `start` or `supervised`; the client value
  survives restarts;
- login takes the browser's `Request` and Warden sets the binding cookie;
  `complete_login` returns `Result(Session, LoginError)`;
- `access_token`, `refresh` and `recover_refresh` replace
  `session_access_token`, `refresh_session` and `recover_refresh_publication`,
  and no failure is inside `Ok`;
- logout revokes the refresh token and returns a record; the provider
  redirect is opaque;
- `warden/observation` is `warden/telemetry`;
- new modules: `warden/store`, `warden/resource`, `warden/testing`.

A dependent that imports `gleam/time/duration` or `gleam/time/timestamp`
adds `gleam_time = ">= 1.11.0 and < 2.0.0"` to its `gleam.toml`; one that
builds `Request`/`Response` values already has `gleam_http`.

Contents: [warden/config](#wardenconfig) · [warden: lifecycle](#warden-lifecycle) ·
[warden: failures](#warden-failure-vocabulary) · [warden: login](#warden-login) ·
[warden: identity](#warden-identity) · [warden: sessions](#warden-sessions-and-access-tokens) ·
[warden: userinfo and client credentials](#warden-userinfo-and-client-credentials) ·
[warden: introspection](#warden-introspection) · [warden: logout](#warden-logout) ·
[warden/telemetry](#wardenobservation--wardentelemetry) · [new modules](#new-modules) ·
[dependents](#dependents)

## `warden/config`

| Before                                                                                                                                                  | After                                                                                                                                                                                                                      |
| ------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pub type Settings { Settings(..18 fields..) }` (public record)                                                                                         | removed; `config.Config` is opaque (an alias of an internal record) built by constructors and setters                                                                                                                      |
| `pub opaque type Config` (validated)                                                                                                                    | `config.Config` is the unvalidated configuration; `warden.new` validates                                                                                                                                                   |
| `config.validate(settings) -> Result(Config, List(ConfigError))`                                                                                        | `config.validate(config) -> Result(Nil, List(ConfigError))` (optional; `warden.new` runs it and returns `InvalidConfig(errors)`)                                                                                           |
| `config.new(issuer:, client_id:, redirect_uri:, authentication:) -> Settings`                                                                           | same arguments, returns `Config`                                                                                                                                                                                           |
| —                                                                                                                                                       | `config.service_client(issuer:, client_id:, authentication:)`: no redirect URI, no login; refuses `PublicClient` (`ServiceClientNeedsCredentials`)                                                                         |
| —                                                                                                                                                       | `config.resource_server(issuer:)`: local token validation only                                                                                                                                                             |
| `pub type Transport { Transport(trust, destinations, allowed_hosts, request_timeout_ms, max_response_bytes) }`, `default_transport()`, `with_transport` | removed; use `with_trust`, `with_destinations`, `with_allowed_hosts(List(String))`, `with_request_timeout(Duration)`, `with_max_response_bytes(Int)`                                                                       |
| `with_login_lifetime(settings, seconds: Int)`                                                                                                           | `with_login_lifetime(config, Duration)`                                                                                                                                                                                    |
| `with_session_lifetime(settings, absolute: Int, idle: Int)`                                                                                             | `with_session_lifetime(config, absolute: Duration, idle: Duration)`                                                                                                                                                        |
| `with_clock_tolerance(settings, seconds: Int)`                                                                                                          | `with_clock_tolerance(config, Duration)`                                                                                                                                                                                   |
| `Settings(..s, startup_timeout_ms: n)`                                                                                                                  | `with_startup_timeout(config, Duration)`                                                                                                                                                                                   |
| `Settings(..s, store_timeout_ms: n)`                                                                                                                    | `with_store_timeout(config, Duration)`                                                                                                                                                                                     |
| `Settings(..s, max_pending_logins: n)`                                                                                                                  | `with_max_pending_logins(config, Int)`                                                                                                                                                                                     |
| `Settings(..s, authentication: a)`                                                                                                                      | pass `authentication` to the constructor                                                                                                                                                                                   |
| —                                                                                                                                                       | `with_login_timeout(Duration)` (default 30 s), `with_refresh_margin(Duration)` (30 s), `with_refresh_wait(Duration)` (5 s)                                                                                                 |
| —                                                                                                                                                       | `with_custody_store(Store)`, `with_transaction_store(Store)`, `with_sealing_key(SealingKey)`, `with_previous_sealing_keys(List(SealingKey))`; `SealingKey`, `sealing_key(BitArray) -> Result(SealingKey, SealingKeyError)` |
| `ConfigError.InvalidLimit(String)`                                                                                                                      | `InvalidLimit(Limit)` with `Limit { RequestTimeout MaxResponseBytes StartupTimeout StoreTimeout LoginTimeout LoginLifetime MaxPendingLogins SessionLifetime ClockTolerance RefreshMargin RefreshWait }`                    |
| `ConfigError.InvalidSessionLifetime`                                                                                                                    | `InvalidLimit(SessionLifetime)`                                                                                                                                                                                            |
| —                                                                                                                                                       | `ConfigError.ServiceClientNeedsCredentials`, `SealingKeyRequired`                                                                                                                                                          |
| `string.inspect(errors)`                                                                                                                                | `config.describe_config_error(error)` (names the setter)                                                                                                                                                                   |
| `config.valid_scope`, `config.valid_redirect_uri`, `config.algorithm_name`, `config.TrustAnchors`                                                       | removed (internal)                                                                                                                                                                                                         |
| `config.pkce_advertisement(config)`, `config.session_lifetime(config)`, `config.clock_tolerance_seconds(config)` and the `@internal` accessors          | removed; a configuration is write-only                                                                                                                                                                                     |

Unchanged: `Secret`, `secret`, `SigningKey`, `SigningKeyError`,
`signing_key_from_jwk`, `ClientAuthentication`, `SigningAlgorithm`,
`ResponseMode`, `IssuerParameterPolicy`, `PkceAdvertisementPolicy`,
`Trust`, `DestinationPolicy`, `with_scopes`, `with_response_mode`,
`with_signing_algorithms`, `with_trust`, `with_destinations`,
`with_pkce_advertisement`, `with_issuer_parameter`.

```gleam
// Before
let transport =
  config.Transport(
    ..config.default_transport(),
    trust: config.TrustAnchorsPem(ca_pem),
    destinations: config.AllowLoopbackForTesting,
  )
use validated <- result.try(
  config.new(issuer:, client_id:, redirect_uri:, authentication:)
  |> config.with_scopes(["reports"])
  |> config.with_transport(transport)
  |> config.with_clock_tolerance(60)
  |> config.validate
  |> result.map_error(fn(e) { "warden config: " <> string.inspect(e) }),
)
warden.start(validated)

// After
let configuration =
  config.new(issuer:, client_id:, redirect_uri:, authentication:)
  |> config.with_scopes(["reports"])
  |> config.with_trust(config.TrustAnchorsPem(ca_pem))
  |> config.with_destinations(config.AllowLoopbackForTesting)
  |> config.with_clock_tolerance(duration.seconds(60))
use client <- result.try(
  warden.new(configuration)
  |> result.map_error(warden.describe_start_error),
)
warden.start(client) |> result.map_error(warden.describe_start_error)
```

## `warden`: lifecycle

| Before                                                                                                                                                               | After                                                                                                                                  |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `warden.start(config) -> Result(Client, StartError)`                                                                                                                 | `warden.new(config) -> Result(Client, StartError)` (validates; starts nothing), then `warden.start(client) -> Result(Nil, StartError)` |
| `warden.supervised(config) -> ChildSpecification(Client)` (handle invalid after a restart)                                                                           | `warden.supervised(client) -> ChildSpecification(Client)`: starts at once, discovers in the background, names survive restarts         |
| `warden.stop(client)`                                                                                                                                                | unchanged (a supervised client is stopped through its parent)                                                                          |
| `StartError { DiscoveryFailed ProviderIncompatible StartupTimedOut ProcessStartFailed }`                                                                             | also `InvalidConfig(List(ConfigError))`, `AlreadyStarted`; `describe_start_error`                                                      |
| `InitFailed("warden failed to start")`                                                                                                                               | `InitFailed(describe_start_error(error))`                                                                                              |
| —                                                                                                                                                                    | `warden.with_correlation(client, correlation) -> Client`: a pure view; events and HTTP Gun requests carry the correlation              |
| `@internal start_with_clock`, `start_with_clocks`, `transaction_store`, `custody_owner`, `http_policy`, `provider_worker`, `supervisor_pid`, `call_error_is_timeout` | removed; tests read the client record (`warden/internal/runtime`) and set the internal clock field                                     |

```gleam
// Before
let assert Ok(client) = warden.start(validated)
supervisor.add(builder, warden.supervised(validated))

// After
let assert Ok(client) = warden.new(configuration)
let assert Ok(Nil) = warden.start(client)
// or, under a supervisor, with the same client value afterwards:
supervisor.add(builder, warden.supervised(client))
```

## `warden`: failure vocabulary

| Before                                                  | After                                                                                                                       |
| ------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `TransportFailure(sent: Bool, reason: TransportReason)` | `TransportFailure(evidence: Evidence, reason: TransportReason)`, `Evidence { NotSent MaybeSent }`                           |
| —                                                       | `describe_provider_failure(ProviderFailure) -> String`                                                                      |
| —                                                       | `Action { Reauthenticate RetryLater Recover FixConfiguration RejectRequest }`, `login_error_action`, `session_error_action` |

`TransportReason`, `OAuthError`, `Incompatibility` and `ProviderFailure`'s
other variants are unchanged.

```gleam
// Before
warden.TransportFailure(sent: False, reason: warden.ConnectionRefused)
// After
warden.TransportFailure(evidence: warden.NotSent, reason: warden.ConnectionRefused)
```

## `warden`: login

| Before                                                                                                                                 | After                                                                                                                                                                                                                                     |
| -------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pub opaque type BrowserBinding`, `browser_binding_value`, `parse_browser_binding`                                                     | removed: Warden reads and sets the `__Host-warden_binding` cookie                                                                                                                                                                         |
| `begin_login(client, Option(BrowserBinding), LoginOptions) -> Result(LoginRedirect, BeginLoginError)`                                  | `begin_login(client, request: Request(a), options) -> Result(LoginRedirect, LoginError)`; the browser's existing binding cookie is reused                                                                                                 |
| `LoginRedirect(url: String, browser_binding: BrowserBinding)` (record)                                                                 | opaque `LoginRedirect`; `login_url(redirect) -> String`; `login_response(response, redirect) -> Response(b)` (303, `Location`, binding cookie, `Cache-Control: no-store`)                                                                 |
| `LoginOptions(.., max_age: Option(Int), ..)`                                                                                           | `max_age: Option(Duration)`; option values are limited to 2 KiB (`OptionTooLong(name)`)                                                                                                                                                   |
| `BeginLoginError { InvalidLoginOption LoginProviderUnavailable LoginProviderIncompatible LoginStoreUnavailable TooManyPendingLogins }` | merged into `LoginError` (same constructor names) plus `LoginNotConfigured`                                                                                                                                                               |
| `Callback { QueryCallback(String) FormPostCallback(String) }`                                                                          | removed                                                                                                                                                                                                                                   |
| `complete_login(client, Callback, Option(BrowserBinding)) -> Result(LoginCompletion, LoginError)`                                      | `complete_login(client, request: Request(String)) -> Result(Session, LoginError)`: a `GET` with the query, or a `POST` with an `application/x-www-form-urlencoded` body, carrying the binding cookie; bounded by the login timeout (30 s) |
| `LoginCompletion { LoginCompleted(Session) LoginRecoveryRequired(CustodyRecovery) }`                                                   | `Ok(session)` / `Error(CustodyUnconfirmed(recovery))`                                                                                                                                                                                     |
| `recover_custody(client, recovery) -> Result(CustodyRecoveryResult, CustodyRecoveryError)`                                             | `recover_custody(client, recovery) -> Result(Session, LoginError)`                                                                                                                                                                        |
| `CustodyRecoveryResult { CustodyRecovered(Session) CustodyStillUncertain(CustodyRecovery) }`                                           | `Ok(session)` / `Error(CustodyUnconfirmed(recovery))`                                                                                                                                                                                     |
| `CustodyRecoveryError { RecoveryOwnerMismatch ContradictoryReceipt RecoveryEnded RecoveryExpired }`                                    | `LoginError.RecoveryForeign`, `RecoveryEnded`, `RecoveryExpired` (a contradictory receipt cannot occur; it reads as `RecoveryEnded`)                                                                                                      |
| —                                                                                                                                      | `LoginError.LoginTimedOut`, `LoginRecordUnreadable` (a sealed login that does not open); `describe_login_error`                                                                                                                           |

Unchanged: `Prompt`, `default_login`, `LoginOptionProblem` (plus
`OptionTooLong`), `CallbackProblem`, `BindingProblem`, `Denial`,
`IdentityProblem`, and every other `LoginError` constructor.

```gleam
// Before (wisp)
let binding =
  wisp.get_cookie(request, "__Host-warden_binding", wisp.PlainText)
  |> result.try(warden.parse_browser_binding)
  |> option.from_result
case warden.begin_login(client, binding, warden.default_login()) {
  Ok(redirect) ->
    wisp.redirect(redirect.url)
    |> wisp.set_cookie(request, "__Host-warden_binding",
      warden.browser_binding_value(redirect.browser_binding), wisp.PlainText, 900)
  Error(error) -> page(503, string.inspect(error))
}

// After
case warden.begin_login(client, request, warden.default_login()) {
  Ok(redirect) -> warden.login_response(wisp.response(303), redirect)
  Error(error) -> page(503, warden.describe_login_error(error))
}
```

```gleam
// Before
case warden.complete_login(client, warden.QueryCallback(query), binding) {
  Ok(warden.LoginCompleted(session)) -> signed_in(session)
  Ok(warden.LoginRecoveryRequired(recovery)) ->
    case warden.recover_custody(client, recovery) {
      Ok(warden.CustodyRecovered(session)) -> signed_in(session)
      _ -> try_later()
    }
  Error(error) -> failed(error)
}

// After: GET callback (a form-post callback passes the POST body instead)
let callback = request.set_body(request, "")
case warden.complete_login(client, callback) {
  Ok(session) -> signed_in(session)
  Error(warden.CustodyUnconfirmed(recovery)) ->
    case warden.recover_custody(client, recovery) {
      Ok(session) -> signed_in(session)
      Error(_) -> try_later()
    }
  Error(error) ->
    case warden.login_error_action(error) {
      warden.RejectRequest -> bad_request(warden.describe_login_error(error))
      _ -> sign_in_again()
    }
}
```

## `warden`: identity

| Before                                         | After                  |
| ---------------------------------------------- | ---------------------- |
| `authentication_time(identity) -> Option(Int)` | `-> Option(Timestamp)` |

Unchanged: `VerifiedIdentity`, `IdentityKey`, `identity_key`, `issuer`,
`subject`, `email`, `email_verified`, `name`, `preferred_username`, `acr`,
`amr`, `decode_claims`, `session_identity`, `session_reference`.

## `warden`: sessions and access tokens

| Before                                                                                                         | After                                                                                                                                                                                                                                                                                                                                                                  |
| -------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `session_revision(session) -> Int`                                                                             | removed; operations use custody's current revision                                                                                                                                                                                                                                                                                                                     |
| `session_access_token(client, session) -> Result(#(AccessToken, Option(Int)), SessionError)`                   | `access_token(client, session) -> Result(Access, SessionError)`; `Access(session:, token:, expires_at: Option(Timestamp), scopes:)`; refreshes within the refresh margin                                                                                                                                                                                               |
| `session_scopes(client, session)`                                                                              | `Access.scopes`                                                                                                                                                                                                                                                                                                                                                        |
| `refresh_session(client, session) -> Result(RefreshResult, RefreshError)`                                      | `refresh(client, session) -> Result(Access, SessionError)` (forced, after a 401; an older session value gets the current token without a second refresh)                                                                                                                                                                                                               |
| `recover_refresh_publication(client, RefreshPublicationRecovery) -> Result(RefreshResult, RefreshError)`       | `recover_refresh(client, RefreshRecovery) -> Result(Access, SessionError)`                                                                                                                                                                                                                                                                                             |
| `RefreshPublicationRecovery`                                                                                   | `RefreshRecovery` (carried by `SessionError.RefreshUnconfirmed`)                                                                                                                                                                                                                                                                                                       |
| `RefreshReservationRecovery`, `reservation_recovery_reference`                                                 | removed (a quarantine is custody state)                                                                                                                                                                                                                                                                                                                                |
| `authorization_header(token) -> #(String, String)`                                                             | `authorize(request: Request(a), token) -> Request(a)`                                                                                                                                                                                                                                                                                                                  |
| `SessionError { SessionNotFound SessionForeign SessionStale SessionStoreUnavailable SessionHasNoAccessToken }` | `SessionStale` removed; adds `SessionLost`, `SessionRecordUnreadable`, `RefreshTokenUnavailable`, `RefreshRevoked`, `RefreshRejected(OAuthError)`, `RefreshNotSent(ProviderFailure)`, `RefreshQuarantined(QuarantineReason)`, `RefreshWaitTimedOut`, `RefreshUnconfirmed(RefreshRecovery)`, `RefreshRecoveryForeign`; `describe_session_error`, `session_error_action` |
| `RefreshResult.RefreshCompleted(Session)`                                                                      | `Ok(access)` (`access.session`)                                                                                                                                                                                                                                                                                                                                        |
| `RefreshResult.RefreshDidNotSend(f)`                                                                           | `Error(RefreshNotSent(f))`                                                                                                                                                                                                                                                                                                                                             |
| `RefreshResult.RefreshRejectedByEndpoint(InvalidGrant)`                                                        | `Error(RefreshRevoked)`                                                                                                                                                                                                                                                                                                                                                |
| `RefreshResult.RefreshRejectedByEndpoint(code)` (other codes)                                                  | `Error(RefreshRejected(code))`                                                                                                                                                                                                                                                                                                                                         |
| `RefreshResult.RefreshProviderQuarantined(_)`                                                                  | `Error(RefreshQuarantined(ProviderOutcomeUnknown))`                                                                                                                                                                                                                                                                                                                    |
| `RefreshResult.RefreshResponseQuarantined(problem, _)`                                                         | `Error(RefreshQuarantined(ResponseRejected(problem)))`                                                                                                                                                                                                                                                                                                                 |
| `RefreshResult.RefreshReservationUnresolved(_)`                                                                | `Error(SessionStoreUnavailable)` (the lease then quarantines: `RefreshQuarantined(RefresherLost)`)                                                                                                                                                                                                                                                                     |
| `RefreshResult.RefreshPublicationUnresolved(r)`                                                                | `Error(RefreshUnconfirmed(r))`                                                                                                                                                                                                                                                                                                                                         |
| `RefreshError.RefreshSessionForeign` / `RecoveryForeign`                                                       | `SessionForeign` / `RefreshRecoveryForeign`                                                                                                                                                                                                                                                                                                                            |
| `RefreshError.RefreshSessionMissing`                                                                           | `SessionNotFound` (or `SessionLost`)                                                                                                                                                                                                                                                                                                                                   |
| `RefreshError.RefreshSessionStale`                                                                             | gone: the current revision is used                                                                                                                                                                                                                                                                                                                                     |
| `RefreshError.RefreshInProgress`                                                                               | gone: the request waits for the other refresh (default 5 s), else `RefreshWaitTimedOut`                                                                                                                                                                                                                                                                                |
| `RefreshError.RefreshQuarantined`                                                                              | `RefreshQuarantined(reason)`                                                                                                                                                                                                                                                                                                                                           |
| `RefreshError.RefreshTokenUnavailable`, `RefreshRevoked`                                                       | same names, in `SessionError`                                                                                                                                                                                                                                                                                                                                          |
| `RefreshError.RefreshStoreUnavailable`                                                                         | `SessionStoreUnavailable`                                                                                                                                                                                                                                                                                                                                              |
| `RefreshError.RefreshPublicationRejected`                                                                      | `RefreshQuarantined(RefresherLost)`                                                                                                                                                                                                                                                                                                                                    |

`RefreshValidationError` is unchanged.

```gleam
// Before (sso_portal's access.gleam, abridged: margin, join by polling, restore past stale)
case warden.session_access_token(client, session) {
  Ok(#(token, Some(exp))) if exp - now() > 30 -> Ok(token)
  Ok(_) ->
    case warden.refresh_session(client, session) {
      Ok(warden.RefreshCompleted(next)) -> ...session_access_token(client, next)...
      Error(warden.RefreshInProgress) -> poll_and_retry()
      Error(warden.RefreshSessionStale) -> restore_and_retry()
      Ok(warden.RefreshRejectedByEndpoint(warden.InvalidGrant)) -> reauthenticate()
      _ -> retry_later()
    }
  Error(warden.SessionStale) -> restore_and_retry()
  Error(_) -> reauthenticate()
}
request |> request.set_header(warden.authorization_header(token).0, ..)

// After
case warden.access_token(client, session) {
  Ok(access) -> Ok(warden.authorize(request, access.token))
  Error(error) ->
    case warden.session_error_action(error) {
      warden.Reauthenticate -> reauthenticate()
      warden.Recover -> recover(error)   // RefreshUnconfirmed(r): warden.recover_refresh(client, r)
      _ -> retry_later()
    }
}
// After a 401 from the API:
warden.refresh(client, session)
```

## `warden`: userinfo and client credentials

| Before                                                                                                       | After                                                                |
| ------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------- |
| `userinfo(client, session)` read the token at the session's exact revision (`UserinfoSession(SessionStale)`) | uses `access_token` (refreshes near expiry; no stale error)          |
| `ClientToken(access_token:, expires_in: Option(Int), scopes:)`                                               | `ClientToken(access_token:, expires_at: Option(Timestamp), scopes:)` |
| —                                                                                                            | `describe_userinfo_error`, `describe_client_credentials_error`       |

`UserInfo`, `userinfo_subject`, `decode_userinfo`, `UserinfoError`,
`ClientCredentialsError` and `client_credentials` are otherwise unchanged;
a resource-server client answers `ClientCredentialsNeedConfidentialClient`.

```gleam
// Before
case token.expires_in { Some(seconds) -> schedule(seconds) None -> Nil }
// After
case token.expires_at { Some(at) -> schedule_at(at) None -> Nil }
```

## `warden`: introspection

| Before                                                                                                                                  | After                                                                                                                                                                                                           |
| --------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TokenInfo(client_id, subject, username, scopes, expires_at: Option(Int), issued_at: Option(Int), token_type, issuer, claims: Dynamic)` | `TokenInfo(client_id, subject, username, scopes, audiences: List(String), expires_at: Option(Timestamp), issued_at: Option(Timestamp), not_before: Option(Timestamp), token_type, issuer, claims: TokenClaims)` |
| `decode.run(info.claims, decoder)`                                                                                                      | `warden.decode_token_claims(info, decoder)`                                                                                                                                                                     |
| `ActiveToken` for an expired `exp`                                                                                                      | `InactiveToken` (strict `exp`; `nbf` with the clock tolerance)                                                                                                                                                  |
| a token over 64 KiB failed as a transport error                                                                                         | over 8 KiB: `Error(IntrospectionTokenTooLarge)`, nothing sent (`max_token_bytes`)                                                                                                                               |
| —                                                                                                                                       | `describe_introspection_error`; an empty token is `InactiveToken` without a request                                                                                                                             |

```gleam
// Before (secure_mcp's auth.gleam)
Ok(warden.ActiveToken(info)) ->
  case info.expires_at {
    Some(exp) if exp <= now -> Error(authorization.BearerRejected)
    _ -> {
      let audiences = decode.run(info.claims, audience_decoder()) |> result.unwrap([])
      ...
    }
  }

// After
Ok(warden.ActiveToken(info)) -> {
  // `info.audiences` is already a List(String)
  let attestation =
    authorization.attestation(principal, info.audiences, info.scopes)
  ...
}
```

## `warden`: logout

| Before                                                                   | After                                                                                                                                                                             |
| ------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `LogoutOptions(post_logout_redirect_uri:, state:)`                       | `LogoutOptions(post_logout_redirect_uri:, state:, revocation: RevocationPolicy)`; build from `default_logout()`                                                                   |
| —                                                                        | `default_logout() -> LogoutOptions` (revokes), `RevocationPolicy { RevokeRefreshToken SkipRevocation }`                                                                           |
| `LogoutOutcome { RedirectToProvider(url: String) NoEndSessionEndpoint }` | `LogoutOutcome { LoggedOut(provider_logout: ProviderLogout, revocation: RevocationOutcome) }`                                                                                     |
| —                                                                        | `ProviderLogout { RedirectToProvider(LogoutRedirect) NoEndSessionEndpoint ProviderLogoutUnavailable(ProviderFailure) }`; opaque `LogoutRedirect`, `logout_url`, `logout_response` |
| —                                                                        | `RevocationOutcome { Revoked RevocationUnsupported RevocationFailed(ProviderFailure) RevocationSkipped }`                                                                         |
| `LogoutError.LogoutProviderUnavailable(f)`                               | `Ok(LoggedOut(provider_logout: ProviderLogoutUnavailable(f), ..))` (custody is removed either way)                                                                                |
| —                                                                        | `describe_logout_error`                                                                                                                                                           |

```gleam
// Before
case warden.logout(client, session,
  warden.LogoutOptions(post_logout_redirect_uri: Some(back), state: Some(state))) {
  Ok(warden.RedirectToProvider(url)) -> wisp.redirect(url)
  Ok(warden.NoEndSessionEndpoint) -> wisp.redirect("/")
  Error(warden.LogoutSession(warden.SessionNotFound)) -> wisp.redirect("/")
  Error(_) -> failed()
}

// After
let options =
  warden.LogoutOptions(..warden.default_logout(),
    post_logout_redirect_uri: Some(back), state: Some(state))
case warden.logout(client, session, options) {
  Ok(warden.LoggedOut(provider_logout: warden.RedirectToProvider(redirect), ..)) ->
    warden.logout_response(wisp.response(303), redirect)
  Ok(warden.LoggedOut(..)) -> wisp.redirect("/")
  Error(warden.LogoutSession(warden.SessionNotFound)) -> wisp.redirect("/")
  Error(_) -> failed()
}
```

## `warden/observation` → `warden/telemetry`

| Before                                                             | After                                                                                                                                         |
| ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `import warden/observation`                                        | `import warden/telemetry`                                                                                                                     |
| `observation.http_request()`                                       | `telemetry.http_request()`                                                                                                                    |
| `HttpRequest(method, host, path, outcome)`                         | `HttpRequest(method, host, path, outcome, correlation: Option(Correlation))`                                                                  |
| `Outcome.Failed(sent: Bool, class: String)`                        | `Failed(evidence: Evidence, reason: TransportReason)` (telemetry's own closed types; `transport_reason_name` gives the wire name)             |
| wire: `method => get` (atom), `{failure, sent \| not_sent, Class}` | wire: `method => <<"get">>`, `{failure, maybe_sent \| not_sent, Reason}` with the reason names below                                          |
| —                                                                  | `login()`, `refresh()`, `logout()` descriptors with closed outcomes; `transport_reasons`, `login_outcomes`, `refresh_outcomes`, `revocations` |

Reason names changed for three classes: `body_too_large` →
`response_too_large`, `headers_too_large` → `response_headers_too_large`,
`malformed_response` → `malformed_http`; the rest keep their names
(`internal_error`, `invalid_request` and `no_trust_anchors` become
`other_transport_failure`).

```gleam
// Before
case request.outcome {
  observation.Status(code) -> int.to_string(code)
  observation.Failed(sent: True, class:) -> "failed after send: " <> class
  observation.Failed(sent: False, class:) -> "not sent: " <> class
}
// After
case request.outcome {
  telemetry.Status(code) -> int.to_string(code)
  telemetry.Failed(evidence: telemetry.MaybeSent, reason:) ->
    "failed after send: " <> telemetry.transport_reason_name(reason)
  telemetry.Failed(evidence: telemetry.NotSent, reason:) ->
    "not sent: " <> telemetry.transport_reason_name(reason)
}
```

An application that joined Warden's events to its requests by emitting pid
sets `warden.with_correlation(client, correlation)` instead and reads
`request.correlation`; HTTP Gun's events for Warden's requests carry the
same value.

## New modules

- `warden/store`: `Record(key, version, expires_at: Timestamp, sealed)`,
  `StoreError { StoreUnavailable StoreOutcomeUnknown StoreFull }`, opaque
  `Store`, `new(get:, put:, delete_expired:)`, `get`, `put`,
  `delete_expired`, `describe_error`.
- `warden/resource`: `Validator`, `new(client, audience:)`,
  `with_audience_policy`, `with_algorithms`, `with_required_scopes`,
  `allow_any_token_type`, `verify(validator, token) -> Result(AccessClaims,
TokenError)`, `AccessClaims` accessors (`issuer`, `subject`, `client_id`,
  `audiences`, `scopes`, `expires_at`, `issued_at`, `jwt_id`,
  `decode_claims`), `TokenError`, `ErrorKind { Rejected Forbidden
Unavailable }`, `error_kind`, `describe_error`, `verifier` (adapter for
  Relay's `authorization.verifier`).
- `warden/testing`: `start_provider(provider_options())`, option setters
  (`with_client`, `with_access_token_ttl`, `with_access_token_audiences`,
  `with_refresh_delay`), `stop_provider`, `issuer`, `client_id`,
  `trust_anchor_pem`, `config`, `service_config`, `trusting`, `authorize`,
  `browser_request`, `requests`, `revoke_refresh_tokens`,
  `set_clock_skew`, `rotate_signing_key`, `access_token` and its setters,
  `forged(spec, Forgery)`, `issue_access_token`, `memory_store`,
  `check_store`.

## Dependents

Only the two oversight apps import Warden. No package under
`/code/gleam-dream/*/src`, `*/test`, `*/integrations` or `*/consumers`
does; relay does not depend on Warden (the Relay recipe is an adapter
function in `warden/resource`, see the README).

### apps/secure_mcp — moderate break

| File                                                                          | Warden symbols used                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Change                                                                                                                                                                                                                                 |
| ----------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/secure_mcp/app.gleam`                                                    | `warden.Client`, `warden.start`, `warden.stop`, `config.new`, `config.secret`, `config.ClientSecretBasic`, `config.with_scopes`, `config.Transport`, `config.default_transport`, `config.with_transport`, `config.TrustAnchorsPem`, `config.AllowLoopbackForTesting`, `config.validate`                                                                                                                                                                                            | `with_trust` + `with_destinations` instead of `Transport`; `warden.new` + `warden.start`; `describe_start_error` instead of `string.inspect`. With `warden/testing`, `testing.config(provider, redirect_uri)` replaces the whole block |
| `src/secure_mcp/web.gleam`                                                    | `warden.begin_login`, `warden.default_login`, `warden.LoginOptions`, `warden.parse_browser_binding`, `warden.browser_binding_value`, `warden.complete_login`, `warden.QueryCallback`, `warden.LoginCompleted`, `warden.LoginRecoveryRequired`, `warden.recover_custody`, `warden.CustodyRecovered`, `warden.restore_session`, `warden.session_access_token`, `warden.access_token_value`, `warden.session_reference`, `warden.session_identity`, `warden.subject`, `warden.Client` | login routes per [login](#warden-login) (drop the binding cookie code; `login_response`); `access_token(client, session)` and `access.token` instead of `session_access_token`                                                         |
| `src/secure_mcp/auth.gleam`                                                   | `warden.introspect`, `warden.ActiveToken`, `warden.InactiveToken`, `warden.IntrospectionNotSupported`, `warden.IntrospectionFailed`, `warden.Client`                                                                                                                                                                                                                                                                                                                               | delete the `exp` re-check and the `aud` decoder (`info.audiences`); handle `IntrospectionTokenTooLarge` as `BearerRejected`. Or switch to `warden/resource` with the one-line Relay verifier                                           |
| `src/secure_mcp/telemetry.gleam`                                              | `observation.http_request`, `observation.Status`, `observation.Failed`                                                                                                                                                                                                                                                                                                                                                                                                             | `warden/telemetry`; `Failed(evidence:, reason:)`; `request.correlation` replaces the pid bridge (SMCP-9)                                                                                                                               |
| `src/secure_mcp/dev_provider.gleam`, `src/secure_mcp_dev_ffi.erl` (459 lines) | none (its own provider)                                                                                                                                                                                                                                                                                                                                                                                                                                                            | replaceable by `warden/testing` (`issue_access_token`, `revoke_refresh_tokens`, introspection, `trust_anchor_pem`)                                                                                                                     |

### apps/sso_portal — heavy break

| File                                                                               | Warden symbols used                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Change                                                                                                                                                                                                          |
| ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/sso_portal/app.gleam`                                                         | `warden.Client`, `warden.start`, `warden.stop`, `config.new`, `config.secret`, `config.ClientSecretBasic`, `config.with_scopes`, `config.with_trust`, `config.TrustAnchorsPem`, `config.with_destinations`, `config.AllowLoopbackForTesting`, `config.with_clock_tolerance(Int)`, `config.validate`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | `with_clock_tolerance(duration.seconds(n))`; `warden.new` + `warden.start`. A durable Postgres `warden/store` adapter (one table) replaces the custody workaround (SSO-1); `restart_warden` then keeps sessions |
| `src/sso_portal/web.gleam`                                                         | `warden.begin_login`, `warden.default_login`, `warden.parse_browser_binding`, `warden.browser_binding_value`, `warden.complete_login`, `warden.QueryCallback`, `warden.LoginCompleted`, `warden.LoginRecoveryRequired`, `warden.recover_custody`, `warden.CustodyRecovered`, `warden.LoginError` and its variants (`CallbackMalformed`, `CallbackRejected`, `LoginExpired`, `LoginReplayed`, `LoginChanged`, `TransactionStoreUnavailable`, `ProviderDenied`, `ProviderUnavailableBeforeExchange`, `ExchangeRejected`, `ExchangeOutcomeUnknown`, `IdentityRejected`), `warden.restore_session`, `warden.SessionStoreUnavailable`, `warden.logout`, `warden.LogoutOptions`, `warden.RedirectToProvider`, `warden.NoEndSessionEndpoint`, `warden.session_reference`, `warden.session_identity`, `warden.subject`, `warden.issuer`, `warden.email`, `warden.Session`, `warden.Client` | login per [login](#warden-login); the 31-line `LoginError` map becomes `login_error_action` plus `describe_login_error`; logout per [logout](#warden-logout) (revocation is now automatic: SSO-2)               |
| `src/sso_portal/access.gleam` (160 lines)                                          | `warden.session_access_token`, `warden.refresh_session`, `warden.recover_refresh_publication`, `warden.session_revision`, `warden.restore_session`, `warden.session_reference`, `warden.AccessToken`, `warden.Session`, `warden.Client`, `warden.SessionError` (`SessionStale`, `SessionNotFound`, `SessionForeign`, `SessionStoreUnavailable`, `SessionHasNoAccessToken`), every `RefreshResult` and `RefreshError` variant, `warden.InvalidGrant`, `warden.RecoveryForeign`                                                                                                                                                                                                                                                                                                                                                                                                      | the whole module becomes `warden.access_token` (margin, join, stale handling) plus `session_error_action`; after a 401, `warden.refresh` (see [sessions](#warden-sessions-and-access-tokens))                   |
| `src/sso_portal/billing.gleam`                                                     | `warden.authorization_header`, `warden.AccessToken`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | `warden.authorize(request, token)`                                                                                                                                                                              |
| `src/sso_portal/telemetry.gleam`                                                   | `observation.http_request`, `observation.Status`, `observation.Failed`, `observation.Get`, `observation.Post`, `warden.http` (event name)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | `warden/telemetry`; `request.correlation` and `warden.with_correlation` replace the pid links (SSO-7); new `login`, `refresh`, `logout` events                                                                  |
| `test/sso_portal_test.gleam`                                                       | `warden.restore_session`, `warden.refresh_session`, `warden.RefreshCompleted`, `warden.logout`, `warden.LogoutOptions`, `warden.SessionNotFound`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | `warden.refresh` → `Ok(access)`; `warden.LogoutOptions(..warden.default_logout(), ..)`; the expected log line `[warden.http.request] POST /token -> 200` is unchanged                                           |
| `src/sso_portal/fake_idp.gleam`, `pki.gleam`, `sso_portal_pki_ffi.erl` (644 lines) | none (its own provider)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | replaceable by `warden/testing` (`with_refresh_delay`, `set_clock_skew`, `revoke_refresh_tokens`, `requests`)                                                                                                   |
