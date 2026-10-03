# Changelog

All notable changes to `warden` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the package
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The design
decisions behind these entries are in [docs/decisions.md](docs/decisions.md),
and the evidence for each wave in [docs/PROGRESS.md](docs/PROGRESS.md).

## Unreleased

### Changed (breaking, release wave 4; see docs/migration-wave-4.md)

- `Config` is opaque, built by `config.new`, `config.service_client` (no
  redirect URI, no login) or `config.resource_server` (token validation
  only) and flat `with_*` setters. Every timeout, lifetime, tolerance,
  margin and wait is a `gleam/time/duration.Duration`. `Settings`,
  `Transport`, `default_transport`, `with_transport` and the public
  accessors are removed; `config.validate` returns `Result(Nil,
List(ConfigError))`; `InvalidLimit` names a `Limit` and
  `describe_config_error` names the setter.
- Lifecycle: `warden.new(config)` validates and allocates the client's
  process names once; `warden.start(client)` discovers and starts;
  `warden.supervised(client)` starts at once and discovers in the
  background, so the client survives supervisor restarts and a provider
  outage at boot does not fail the parent tree.
- Login takes and returns gleam_http values: `begin_login(client, request,
options)` reads the browser-binding cookie, `login_response` sets it
  (`__Host-warden_binding`, `Secure`, `HttpOnly`, `SameSite` by response
  mode, `no-store`), `complete_login(client, request)` takes the callback
  request and returns `Result(Session, LoginError)`. `LoginError` absorbs
  `BeginLoginError` and the custody-recovery errors, and gains
  `CustodyUnconfirmed(recovery)`, `LoginTimedOut`, `LoginNotConfigured` and
  `LoginRecordUnreadable`.
- Sessions: `access_token(client, session)` (refreshes within 30 s of
  expiry, waits up to 5 s for another request's refresh, uses the current
  revision), `refresh` and `recover_refresh` return `Result(Access,
SessionError)`; no failure is inside `Ok`. `authorize(request, token)`
  replaces `authorization_header`.
- Logout returns `LoggedOut(provider_logout:, revocation:)`; the provider
  redirect is an opaque `LogoutRedirect` (its URL holds the ID token) with
  `logout_url` and `logout_response`; `default_logout()` revokes the
  refresh token (RFC 7009).
- Introspection: `TokenInfo` gains `audiences` and `not_before`, holds its
  claims for `decode_token_claims`, and uses `Timestamp`s; an expired or
  not-yet-valid token is `InactiveToken`; a token over 8 KiB is refused
  without a request.
- Transport failures carry `evidence: NotSent | MaybeSent`;
  `ClientToken.expires_at` and `authentication_time` are `Timestamp`s.
- `warden/observation` is `warden/telemetry`: typed reasons, evidence and
  correlation in every event.
- Session and login lifetimes are wall-clock time (decision D20).

### Added

- `warden/store`: a compare-and-set storage port for durable, multi-node
  custody and pending logins, with AES-256-GCM sealed records
  (`config.with_custody_store`, `with_transaction_store`,
  `with_sealing_key`, `with_previous_sealing_keys`).
- `warden/resource`: local validation of RFC 9068 JWT access tokens, with
  typed claims and errors and a one-line adapter for Relay's verifier.
- `warden/testing`: a scripted provider with its own test PKI (login,
  refresh, client credentials, userinfo, introspection, revocation,
  end-session, token minting and forgery, clock skew, key rotation, request
  counts), an in-memory store and `check_store`.
- `[warden, login]`, `[warden, refresh]` and `[warden, logout]` events, and
  `warden.with_correlation`, which also tags Warden's HTTP Gun requests.
- `login_error_action` and `session_error_action` return a closed
  `Action`; every error type has a `describe_*` function.
- One 30 s bound on `complete_login` (`config.with_login_timeout`); login
  option values are limited to 2 KiB.
- `SessionLost` for a session lost when the in-memory custody restarted.

### Fixed

- The logout redirect no longer prints the ID token in `string.inspect`.
- `restore_session`, `access_token` and `refresh` carry the caller's
  correlation into the `/token` request (via `with_correlation`).
- HTTP Gun's connect, pool and idle bounds are no longer raised to the
  request timeout.
- Provider-cache calls wait one request timeout, so a slow key refetch no
  longer reports `UnknownSigningKey` early.

### Removed

- `QueryCallback`/`FormPostCallback` (`Callback`), `BrowserBinding`,
  `browser_binding_value`, `parse_browser_binding`, `LoginCompletion`,
  `CustodyRecoveryResult`, `CustodyRecoveryError`, `session_revision`,
  `session_access_token`, `session_scopes` (now `Access.scopes`),
  `refresh_session`, `RefreshResult`, `RefreshError`,
  `RefreshReservationRecovery`, `reservation_recovery_reference`,
  `RefreshPublicationRecovery`, `recover_refresh_publication`,
  `authorization_header`, `BeginLoginError`, the `@internal` test hooks,
  and the public config helpers (`valid_scope`, `valid_redirect_uri`,
  `algorithm_name`, `TrustAnchors`, accessors).

### Earlier unreleased work

#### Added

- An OpenID Connect relying party (`warden`, `warden/config`): discovery,
  key caching, the authorization code flow with PKCE S256, nonce and state,
  query and form-post callbacks bound to the browser, and ID-token
  validation on gose and kryptos. One backend, written in Gleam; oidcc
  3.9.0 is a test-only differential oracle.
- Atomic login transactions (replay, concurrent callbacks, expiry) and a
  custody owner for sessions with absolute and idle lifetimes, refresh with
  at most one outstanding request per generation, and recovery values for
  uncertain custody installation or refresh publication.
- Userinfo, client credentials, token introspection and RP-initiated
  logout.
- Client authentication by `client_secret_basic`, `client_secret_post`,
  `client_secret_jwt` and `private_key_jwt`, never falling back to another
  method. Client secrets, signing keys, access tokens, browser bindings,
  session references and raw claims are held in closures, so
  `string.inspect` and crash reports do not print them.
- HTTPS through a supervised HTTP Gun client per Warden client, under a
  destination policy, verified TLS and bounded responses.
- Warden labels its HTTP Gun client `"warden"` (`config.with_label`), so
  an application can filter or route Warden's HTTP events by the `client`
  key in their metadata.
- An explicit opt-in, `AssumeS256WhenUnadvertised`, for providers that do
  not advertise PKCE methods; the default still requires advertised S256.
- Typed Sinal observations of provider requests (`warden/observation`).
- Tests that `string.inspect` of settings and validated configurations
  (with every client authentication method), `Secret`, `SigningKey`,
  `AccessToken`, session access-token results, refresh results, client
  credentials tokens, introspection results and their errors prints no
  client secret, private key or token.

#### Fixed

- `docs/PROGRESS.md` no longer lists D7 as an open decision; the decision
  register records it as resolved.
- `warden.stop` returns once the supervisor has exited (at most five
  seconds), so a request started afterwards fails as not sent.
