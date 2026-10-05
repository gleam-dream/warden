# warden

A typed Gleam OpenID Connect relying party, OAuth 2.0 client and JWT
resource-server validator for Erlang/OTP. Warden owns discovery, key
caching, the provider requests and the OpenID claim rules; signatures and
keys are handled by [gose](https://github.com/jtdowney/gose) and kryptos,
and HTTPS by [HTTP Gun](https://github.com/gleam-dream/http_gun)
(destination policy, verified TLS, bounded responses) under Warden's
application policy. Every security default fails closed.

Status: **unreleased, pre-production.** HTTP Gun and Sinal are local path
dependencies until they are published. The accepted design is
[warden-design.md](https://github.com/gleam-dream/oversight/blob/master/warden-design.md).
Production use requires the design's release gates and an independent
security review of Warden-owned code. Warden is **not certified**. See
[docs/PROGRESS.md](docs/PROGRESS.md).

## Sign a user in, then call an API

```gleam
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/result
import warden
import warden/config

pub fn start(secret: String) -> Result(warden.Client, warden.StartError) {
  let config =
    config.new(
      issuer: "https://login.example.com",
      client_id: "app",
      redirect_uri: "https://app.example.com/auth/callback",
      authentication: config.ClientSecretBasic(config.secret(secret)),
    )
    |> config.with_scopes(["email", "profile"])
  // Validates; starts nothing.
  use client <- result.try(warden.new(config))
  // Discovery, keys, processes.
  use Nil <- result.map(warden.start(client))
  client
}

/// GET /login: Warden sets the browser-binding cookie and the redirect.
pub fn login(client: warden.Client, req: Request(a)) -> Response(String) {
  case warden.begin_login(client, req, warden.default_login()) {
    Ok(redirect) -> warden.login_response(response.new(303), redirect)
    Error(error) ->
      response.new(503) |> response.set_body(warden.describe_login_error(error))
  }
}

/// GET (or POST, for form-post) /auth/callback, with the body as a String.
pub fn callback(
  client: warden.Client,
  req: Request(String),
) -> Result(String, warden.Action) {
  case warden.complete_login(client, req) {
    // Keep the reference in the application's session.
    Ok(session) -> Ok(warden.session_reference(session))
    // Reauthenticate, RejectRequest, Recover, ...
    Error(error) -> Error(warden.login_error_action(error))
  }
}

/// Any later request: a current token, refreshed within 30 s of expiry;
/// concurrent requests share one refresh.
pub fn call_api(
  client: warden.Client,
  reference: String,
  api_request: Request(a),
) -> Result(Request(a), warden.SessionError) {
  use session <- result.try(warden.restore_session(client, reference))
  use access <- result.map(warden.access_token(client, session))
  warden.authorize(api_request, access.token)
}

/// POST /logout: custody removed, refresh token revoked (RFC 7009).
pub fn logout(
  client: warden.Client,
  session: warden.Session,
) -> Response(String) {
  case warden.logout(client, session, warden.default_logout()) {
    Ok(warden.LoggedOut(
      provider_logout: warden.RedirectToProvider(redirect),
      ..,
    )) -> warden.logout_response(response.new(303), redirect)
    _ -> response.new(303) |> response.set_header("location", "/")
  }
}
```

This code is compiled with the reference consumer
([`consumer/src/warden_reference/readme.gleam`](consumer/src/warden_reference/readme.gleam)),
and the same path runs against the test provider in
[`consumer/test/warden_reference_test.gleam`](consumer/test/warden_reference_test.gleam)
(`common_path_test`). A complete reference relying party lives in
[`consumer/`](consumer/).

Errors are typed unions that may gain variants. Branch on the closed
`Action` that `login_error_action` and `session_error_action` return
(`Reauthenticate`, `RetryLater`, `Recover`, `FixConfiguration`,
`RejectRequest`) and log with the `describe_*` functions. An uncertain
outcome is never `RetryLater` of the same request: a possibly sent
authorization code or refresh token is never sent again.

## Under supervision

```gleam
let assert Ok(client) = warden.new(config)
supervisor.new(supervisor.OneForOne)
|> supervisor.add(warden.supervised(client))
|> supervisor.start
```

`warden.new` allocates the names of the client's processes once, so the
`client` value stays valid when the supervisor restarts them. A supervised
client starts without waiting for the provider and discovers it in the
background (retrying from 1 s to 60 s); until then operations answer
`ProviderNotReady`. A supervised client is stopped through its parent.

Each cache owns at most one asynchronous discovery, metadata reload or key
refresh. Cached reads keep using the last accepted snapshot while it runs.
A cache restart cannot accept an older cache's completion. A whole-tree
restart joins old child processes before reusing their names, bounded by
`config.with_startup_timeout`. Manual startup shares that deadline with
discovery and the first keys. Cache exit terminates its worker without
waiting for the provider deadline or an application telemetry handler.
Shutdown requests supervisor exit and waits up to five seconds; returning
after that bound does not prove shutdown. Worker cancellation follows the
cache's exit notification.

## Durable sessions and several nodes

By default sessions and pending logins live in memory: a restart signs
everyone out (`SessionLost`). Give Warden a table and a sealing key:

```gleam
let records =
  store.new(get: db_get, put: db_put, delete_expired: db_delete_expired)
// 32 bytes from a secret manager.
let assert Ok(key) = config.sealing_key(sealing_key_bytes)
config
|> config.with_custody_store(records)
|> config.with_transaction_store(records)
|> config.with_sealing_key(key)
```

The store needs only compare-and-set on one row (see `warden/store`; a
PostgreSQL adapter is one table and three statements). Every record is
sealed (AES-256-GCM) and bound to its key and version, and keys are
digests, so the database holds no token, verifier or session reference.
Check an adapter with `warden/testing.check_store`.

## Resource servers

```gleam
let assert Ok(client) = warden.new(config.resource_server(issuer:))
let assert Ok(Nil) = warden.start(client)
let validator = resource.new(client, audience: "https://api.example.com")
resource.verify(validator, bearer)   // Result(AccessClaims, TokenError)
```

`warden/resource` validates RFC 9068 JWT access tokens locally with
Warden's key cache: `alg` allowlist (`none` and HMAC unrepresentable),
`typ` `at+jwt`, exact `iss`, exact audience, strict `exp`, `nbf` and `iat`
with the clock tolerance, required scopes. `resource.error_kind` maps an
error to 401, 403, 503 or `WrongAudience`, a valid token issued for another
resource. `resource.verifier` adapts the validator to Relay's
`authorization.verifier`: its `on_error` function maps each `ErrorKind` to
Relay's `VerificationError`, so a wrong-audience token gets Relay's "issued
for another resource" challenge and a missing scope is Relay's to report
(leave `with_required_scopes` unset; Relay's `admit` answers 403). The
introspection recipe tags its provider call with the request's correlation.
`warden.introspect` (RFC 7662) is the alternative for opaque tokens or
immediate revocation: it checks `exp` strictly and `nbf`, refuses tokens over
8 KiB locally, and returns `audiences` and typed claims. Both recipes below
are compiled against Relay by `scripts/relay-recipe` in the gate.

<!-- relay-recipe -->

```gleam
import gleam/option.{type Option, None, Some}
import relay/authorization.{type Attestation, type Verifier}
import warden
import warden/resource

pub type Principal {
  Principal(subject: String, client_id: Option(String), scopes: List(String))
}

/// Local RFC 9068 validation: no provider request per token. A token for
/// another resource gets Relay's "issued for another resource" challenge.
pub fn jwt_verifier(validator: resource.Validator) -> Verifier(Principal) {
  let verify =
    resource.verifier(
      validator,
      authorization.token_value,
      attest,
      on_error: refuse,
    )
  use token, _correlation <- authorization.verifier("warden-jwt")
  verify(token)
}

fn refuse(kind: resource.ErrorKind) -> authorization.VerificationError {
  case kind {
    resource.Rejected | resource.Forbidden -> authorization.BearerRejected
    resource.WrongAudience -> authorization.IssuedForAnotherResource
    resource.Unavailable -> authorization.VerifierUnavailable
  }
}

fn attest(claims: resource.AccessClaims) -> Attestation(Principal) {
  let scopes = resource.scopes(claims)
  authorization.attestation(
    Principal(resource.subject(claims), resource.client_id(claims), scopes),
    resource.audiences(claims),
    scopes,
  )
}

/// RFC 7662 introspection: one provider request per token, so a revoked
/// token is refused at once. The request's correlation tags the provider
/// call, so it joins the MCP request in telemetry.
pub fn introspection_verifier(client: warden.Client) -> Verifier(Principal) {
  use token, correlation <- authorization.verifier("warden-introspection")
  let client = warden.with_correlation(client, correlation)
  case warden.introspect(client, authorization.token_value(token)) {
    Ok(warden.ActiveToken(warden.TokenInfo(subject: Some(subject), ..) as info)) ->
      Ok(authorization.attestation(
        Principal(subject, info.client_id, info.scopes),
        info.audiences,
        info.scopes,
      ))
    Ok(warden.ActiveToken(warden.TokenInfo(subject: None, ..))) ->
      Error(authorization.VerifierUnmapped)
    Ok(warden.InactiveToken) | Error(warden.IntrospectionTokenTooLarge) ->
      Error(authorization.BearerRejected)
    Error(warden.IntrospectionNotSupported)
    | Error(warden.IntrospectionFailed(_)) ->
      Error(authorization.VerifierUnavailable)
  }
}
```

## Several callback addresses

One URI given to `config.new` serves most applications. One served under
several registered callback addresses lists the others, and a login picks
one; the match is exact, and anything else fails closed:

```gleam
let config =
  config.new(
    issuer:,
    client_id:,
    redirect_uri: "https://app.example.com/callback",
    authentication:,
  )
  |> config.with_allowed_redirect_uris(["https://admin.example.com/callback"])

// GET /admin/login
let options =
  warden.LoginOptions(
    ..warden.default_login(),
    redirect_uri: Some("https://admin.example.com/callback"),
  )
warden.begin_login(client, request, options)
// "https://admin.example.com/callback/", or any other near miss:
//   Error(InvalidLoginOption(RedirectUriNotAllowed))
```

The code is exchanged with the URI the login chose. Every allowed URI must
be registered at the provider, and all of them are fixed when `warden.new`
runs ([D36, D37](docs/decisions.md)).

## Testing

`warden/testing` starts a scripted provider over HTTPS on loopback, with
its own PKI, so an application tests its Warden integration without
writing a provider. Its `/authorize` page signs a test user in, so a test
browser follows the application's own `/login` redirect over HTTPS
(trusting `testing.trust_anchor_pem`) and comes back to `/callback` with no
test hook in the application:

```gleam
let assert Ok(provider) =
  testing.start_provider(
    testing.provider_options() |> testing.with_login(testing.SignIn("ada")),
  )
let assert Ok(client) =
  warden.new(testing.config(provider, "https://app.test/callback"))
// /login -> provider /authorize (signs "ada" in) -> /callback?code=...
testing.set_login(provider, testing.Refuse("access_denied"))  // the next one is cancelled
```

A request's `login_hint` picks the user per login. `with_granted_scopes`
sets the scopes one user's login is granted in place of the ones the client
requested, so a test can sign in a user who lacks a scope. The scopes are in
the access token (`resource.scopes`) and at introspection:

```gleam
testing.provider_options()
|> testing.with_granted_scopes("ada", ["openid", "approve:refund"])
|> testing.with_granted_scopes("mallory", ["openid"])
// testing.set_granted_scopes(provider, "mallory", [...]) changes it later
```

Unit tests that hold the `LoginRedirect` skip HTTP:

```gleam
let assert Ok(redirect) =
  warden.begin_login(client, request.new(), warden.default_login())
let assert Ok(callback) = testing.authorize(provider, redirect, subject: "ada")
let assert Ok(session) = warden.complete_login(client, callback)
```

It also mints access tokens (`issue_access_token`, including forged ones),
revokes refresh tokens and single access tokens (`revoke_access_token`),
sets the access-token audience after start
(`set_access_token_audiences`), skews its clock, rotates its key and counts
requests. A revoked access token is refused by introspection at once; a
local JWT validator accepts it until it expires.

## Defaults

| Operation                                                   | Default                                                                                        | Setter                                                         |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `start`: discovery, first keys and previous-process cleanup | 15 s                                                                                           | `config.with_startup_timeout`                                  |
| `supervised`: background discovery                          | retries from 1 s to 60 s                                                                       |                                                                |
| provider request                                            | 10 s; HTTP Gun's own 5 s connect, 5 s pool checkout, 30 s idle read, 60 s idle connection      | `config.with_request_timeout`                                  |
| provider response body                                      | 1 MiB; head 16 KiB, 100 headers; no redirects                                                  | `config.with_max_response_bytes`                               |
| request body Warden sends                                   | 64 KiB                                                                                         |                                                                |
| bearer token introspected or validated                      | 8 KiB                                                                                          |                                                                |
| store call                                                  | 5 s                                                                                            | `config.with_store_timeout`                                    |
| provider-cache call                                         | request timeout + 1 s                                                                          |                                                                |
| `complete_login`, end to end                                | 30 s                                                                                           | `config.with_login_timeout`                                    |
| pending login                                               | 10 min                                                                                         | `config.with_login_lifetime`                                   |
| records in the built-in login store                         | 100 000                                                                                        | `config.with_max_pending_logins`                               |
| callback input                                              | 16 KiB total, 4 KiB per value                                                                  |                                                                |
| login option values                                         | 2 KiB each                                                                                     |                                                                |
| session                                                     | 12 h absolute, 1 h idle                                                                        | `config.with_session_lifetime`                                 |
| sessions per identity                                       | not bounded (decision D14)                                                                     |                                                                |
| refresh margin before expiry                                | 30 s                                                                                           | `config.with_refresh_margin`                                   |
| wait for another request's refresh                          | 5 s                                                                                            | `config.with_refresh_wait`                                     |
| refresh lease (a lost refresher quarantines after it)       | request + 2 × store timeout + 1 s                                                              |                                                                |
| resend after a possible send                                | never (authorization code, refresh token)                                                      |                                                                |
| logout revocation                                           | refresh token revoked (RFC 7009)                                                               | `LogoutOptions(revocation:)`                                   |
| install-recovery horizon, logout tombstones                 | the login lifetime                                                                             |                                                                |
| expired-record sweep                                        | every 60 s                                                                                     |                                                                |
| key cache                                                   | `Cache-Control` clamped to 60 s–24 h, else 1 h                                                 |                                                                |
| unknown-`kid` key refetch                                   | at once per new kid (64 remembered), else once a second                                        |                                                                |
| supervisor restarts                                         | 10 in 60 s                                                                                     |                                                                |
| clock tolerance (`iat`, `nbf`, `auth_time`; never `exp`)    | 5 s                                                                                            | `config.with_clock_tolerance`                                  |
| ID-token and access-token algorithms                        | RS256, PS256, ES256, EdDSA; `none` and HMAC unrepresentable                                    | `config.with_signing_algorithms`, `resource.with_algorithms`   |
| PKCE                                                        | advertised S256 required                                                                       | `config.with_pkce_advertisement`                               |
| RFC 9207 `iss`                                              | required when advertised                                                                       | `config.with_issuer_parameter`                                 |
| destinations, TLS trust                                     | public addresses, system trust                                                                 | `config.with_destinations`, `with_allowed_hosts`, `with_trust` |
| ID-token audience                                           | exactly the client                                                                             |                                                                |
| access-token audience and type (`warden/resource`)          | exactly the configured audience; `typ` `at+jwt`                                                | `resource.with_audience_policy`, `allow_any_token_type`        |
| binding cookie                                              | `__Host-warden_binding`, `Secure`, `HttpOnly`, `Path=/`, `SameSite=Lax` (`None` for form post) |                                                                |
| session and login storage                                   | in memory                                                                                      | `config.with_custody_store`, `with_transaction_store`          |
| `client_credentials`                                        | not cached: one token request per call                                                         |                                                                |

## Modules

| Module             | Purpose                                                                                                  |
| ------------------ | -------------------------------------------------------------------------------------------------------- |
| `warden`           | client lifecycle, login, sessions and access tokens, userinfo, client credentials, introspection, logout |
| `warden/config`    | the opaque `Config`: `new`, `service_client`, `resource_server` and `with_*` setters                     |
| `warden/store`     | the storage port for durable sessions and logins                                                         |
| `warden/resource`  | local JWT access-token validation (RFC 9068)                                                             |
| `warden/telemetry` | typed Sinal events (HTTP requests, login, refresh, logout) with correlation                              |
| `warden/testing`   | scripted provider with a login page and test PKI, in-memory store, store conformance check               |

`warden.with_correlation(client, correlation)` is a pure view whose events
and HTTP Gun requests carry a `sinal/correlation` value. Warden's HTTP Gun
client is labelled `"warden"`.

Application duties (session cookie, rate limits, secrets, clocks) are in
[docs/APPLICATION-RESPONSIBILITIES.md](docs/APPLICATION-RESPONSIBILITIES.md);
decisions in [docs/decisions.md](docs/decisions.md); the wave 4 migration in
[docs/migration-wave-4.md](docs/migration-wave-4.md).

## Development

```sh
nix develop -c scripts/check                 # fast gate: format, build, tests, negative compile, consumer
scripts/keycloak up && WARDEN_SUITE=keycloak gleam test
scripts/node-provider up && WARDEN_SUITE=node gleam test
scripts/interop up && WARDEN_SUITE=interop gleam test      # Dex, Ory Hydra
scripts/browser-journey                      # real Chrome through the reference RP (needs Keycloak)
scripts/conformance-suite up && scripts/conformance        # OpenID RP conformance plans
```

All providers run locally with disposable keys and credentials and a test CA
generated in `build/test-pki`; nothing uses a public demo server or a
production tenant.
