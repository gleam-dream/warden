# Warden usage

Use this guide for supervision, durable stores, resource validation, callback selection and local test providers. The [README](../README.md) shows the ordinary login path; the [application guide](APPLICATION-RESPONSIBILITIES.md) explains the decisions each application must make.

## Under supervision

```gleam
let assert Ok(client) = warden.new(config)
supervisor.new(supervisor.OneForOne)
|> supervisor.add(warden.supervised(client))
|> supervisor.start
```

`warden.new` allocates stable names once, so a `client` handle remains valid
after process replacement. A supervised client discovers in the background;
operations answer `ProviderNotReady` until fresh compatible metadata and keys
arrive. Manual `start` waits for its first discovery attempt. A failed startup
may return while its tree drains, so immediate retry can answer `AlreadyStarted`.

Stop a supervised client through its parent. `stop` observes supervisor exit
for up to five seconds; its return does not prove all resources have finished.
The native design's **Lifecycle and limits** section specifies cache ownership,
restart, timeout and cleanup boundaries. Choose captured-resource lifetime using
the [application guide](APPLICATION-RESPONSIBILITIES.md#resource-lifetime-and-observability).

## Durable sessions and several nodes

By default sessions and pending logins live in memory. A custody-store restart
loses existing sessions (`SessionLost`). Give Warden a table and a sealing key:

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

The [store port](../src/warden/store.gleam) requires atomic compare-and-set
on one row. A PostgreSQL adapter can use one table and three statements. Every record is
sealed (AES-256-GCM) and bound to its key and version, and keys are
digests, so the database holds no token, verifier or session reference.
Check an adapter with `warden/testing.check_store` and the database-specific
race, crash and durability checks described in the [application guide](APPLICATION-RESPONSIBILITIES.md#token-custody-and-persistence).

## Resource servers

```gleam
let assert Ok(client) = warden.new(config.resource_server(issuer:))
let assert Ok(Nil) = warden.start(client)
let validator = resource.new(client, audience: "https://api.example.com")
resource.verify(validator, bearer)   // Result(AccessClaims, TokenError)
```

Stop a manually started client with `warden.stop(client)` when the application
no longer uses it. Stop a supervised client through its parent.

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
8 KiB locally, and returns `audiences` and typed claims. Both recipes in the README
are compiled against Relay by `scripts/relay-recipe` in the gate.

The [Relay recipes in the README](../README.md#resource-servers) show JWT validation and introspection through Relay admission.

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
runs ([trust-policy rationale](adr/0003-strict-oidc-trust-policy.md)).

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
| `complete_login`, effect admission                          | 30 s                                                                                           | `config.with_login_timeout`                                    |
| pending login                                               | 10 min                                                                                         | `config.with_login_lifetime`                                   |
| records in the built-in login store                         | 100 000                                                                                        | `config.with_max_pending_logins`                               |
| callback input                                              | 16 KiB total, 4 KiB per value                                                                  |                                                                |
| login option values                                         | 2 KiB each                                                                                     |                                                                |
| session                                                     | 12 h absolute, 1 h idle                                                                        | `config.with_session_lifetime`                                 |
| sessions per identity                                       | not bounded                                                                                    |                                                                |
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

The login deadline limits effect admission and passes the remaining budget to
provider and store calls. Store cleanup and synchronous telemetry can extend
return latency; see [resource lifetime and observability](APPLICATION-RESPONSIBILITIES.md#resource-lifetime-and-observability).
