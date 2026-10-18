# warden

Warden signs users in with OpenID Connect, obtains OAuth 2.0 tokens and validates
JWT access tokens for Gleam applications on Erlang/OTP. It manages discovery,
signing keys and user-token storage; applications own their session cookies and
permission checks.

## Installation

This checkout is unreleased and pre-production. It requires Gleam 1.18 or later
and uses Git dependencies on the `main` branches of HTTP Gun and Sinal, locked in `manifest.toml`. Gleam fetches them
automatically. For local development, add a Warden checkout to your application's
`gleam.toml` (adjust the path for your directory layout):

```toml
[dependencies]
warden = { path = "../warden" }
```

Production use requires the release conditions in the [design](docs/design/design.typ)
and independent security review of Warden-owned code. Warden is not certified;
the design's validation section states what the retained checks
establish.

## Sign a user in, then call an API

Register the callback address with your issuer and supply the client secret from
trusted configuration. Create one client when the application starts and reuse
it across requests.

<!-- example: consumer/src/warden_reference/usage/login.gleam login -->

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

This block is compiled in
[`usage/login.gleam`](consumer/src/warden_reference/usage/login.gleam), and
[`common_path_test`](consumer/test/warden_reference_test.gleam) runs its path
against the local test provider. The same directory holds one runnable example per
topic below, each run by [`usage_test`](consumer/test/usage_test.gleam).
`scripts/check-doc-examples.py` fails the gate when a block here differs from its
compiled source. The [reference application](consumer/) also supplies browser
routes, application session storage and route protection.

After the application stops admitting requests, call `warden.stop(client)` for
this manually started client. It waits up to five seconds for supervisor exit;
its return does not confirm every worker or external effect has finished. Keep
captured resources alive for the completion boundary your application needs (see the design's "Application responsibilities" section).

## Defaults and failures

Sessions and pending logins use memory by default, so a restart loses sessions.
A session lasts at most 12 hours with a one-hour idle lifetime. `access_token`
refreshes within 30 seconds of expiry, and concurrent requests share one refresh.
Provider requests use verified HTTPS, public destinations and a ten-second
deadline. Login requires advertised S256 PKCE and exact issuer, audience, nonce
and callback matching. Every default and its setter is listed in the design's
"Public defaults and setters" table in [`docs/design/design.typ`](docs/design/design.typ).

`login_error_action` and `session_error_action` return the closed caller actions
`Reauthenticate`, `RetryLater`, `Recover`, `FixConfiguration` and `RejectRequest`.
A possibly sent authorization code or refresh token is never sent again. For
`Recover`, keep the full error and submit its carried value to `recover_custody`
or `recover_refresh`; recovery repeats storage publication without another
provider exchange. Log errors through the `describe_*` functions.

Keep the session reference in a protected application session, use
`(issuer, subject)` as the identity key, and apply application permission and
origin checks on every protected route. The design's "Application
responsibilities" section lists the decisions the application owns, and
[`usage/responsibilities.gleam`](consumer/src/warden_reference/usage/responsibilities.gleam)
runs each one: the identity key, handling for every `Action`, a forced refresh
only for a repeatable request, service-token caching and logout outcomes. The
browser-facing protections (session cookie, same-origin check, response headers)
are in [`protect.gleam`](consumer/src/warden_reference/protect.gleam).

## Supervision

Source: [`usage/supervision.gleam`](consumer/src/warden_reference/usage/supervision.gleam).

<!-- example: consumer/src/warden_reference/usage/supervision.gleam supervision -->

```gleam
pub fn under_supervision(
  configuration: config.Config,
) -> Result(#(warden.Client, actor.Started(supervisor.Supervisor)), String) {
  let assert Ok(client) = warden.new(configuration)
  supervisor.new(supervisor.OneForOne)
  |> supervisor.add(warden.supervised(client))
  |> supervisor.start
  |> result.map(fn(started) { #(client, started) })
  |> result.replace_error("the supervision tree did not start")
}
```

`warden.new` allocates stable names once, so the handle stays valid after process
replacement. A supervised client discovers in the background and answers
`ProviderNotReady` until fresh metadata and keys arrive. Stop a supervised client
through its parent.

## Durable sessions

Source: [`usage/durable_store.gleam`](consumer/src/warden_reference/usage/durable_store.gleam).

<!-- example: consumer/src/warden_reference/usage/durable_store.gleam durable-store -->

```gleam
/// An adapter is three functions. A database table replaces the stand-in.
pub fn adapter(table: store.Store) -> store.Store {
  store.new(
    get: fn(key) { store.get(table, key) },
    put: fn(record, condition) { store.put(table, record, condition) },
    delete_expired: fn(now) { store.delete_expired(table, now) },
  )
}

/// Durable custody and login storage, sealed with a 32-byte key from a
/// secret manager.
pub fn with_durable_store(
  configuration: config.Config,
  records: store.Store,
  sealing_key_bytes: BitArray,
) -> config.Config {
  let assert Ok(key) = config.sealing_key(sealing_key_bytes)
  configuration
  |> config.with_custody_store(records)
  |> config.with_transaction_store(records)
  |> config.with_sealing_key(key)
}
```

Records are sealed with AES-256-GCM, so the database holds no token, verifier or
session reference. The store port has one conditional write with the conditions
`Absent`, `AtVersion` and `AtVersionBefore`; the example runs each outcome and a
second node restoring the first node's session. Check an adapter with
`warden/testing.check_store`; the design's custody section states the contract.
[`warden_postgres`](integrations/warden_postgres/README.md) is a ready adapter.

## Several callback addresses

Source: [`usage/callback_addresses.gleam`](consumer/src/warden_reference/usage/callback_addresses.gleam).

<!-- example: consumer/src/warden_reference/usage/callback_addresses.gleam callback-addresses -->

```gleam
const admin_callback = "https://admin.example.com/callback"

pub fn allow_admin_callback(configuration: config.Config) -> config.Config {
  configuration
  |> config.with_allowed_redirect_uris([admin_callback])
}

/// GET /admin/login
pub fn admin_login(
  client: warden.Client,
  req: request.Request(a),
) -> Result(warden.LoginRedirect, warden.LoginError) {
  let options =
    warden.LoginOptions(
      ..warden.default_login(),
      redirect_uri: Some(admin_callback),
    )
  warden.begin_login(client, req, options)
}
```

A login picks one registered address by exact match; any near miss fails with
`InvalidLoginOption(RedirectUriNotAllowed)`. Register every allowed address with
the provider.

## Testing with a local provider

Source: [`usage/test_provider.gleam`](consumer/src/warden_reference/usage/test_provider.gleam).

<!-- example: consumer/src/warden_reference/usage/test_provider.gleam test-provider -->

```gleam
pub fn sign_in_then_refuse() -> Nil {
  let assert Ok(provider) =
    testing.start_provider(
      testing.provider_options() |> testing.with_login(testing.SignIn("ada")),
    )
  let assert Ok(client) =
    warden.new(testing.config(provider, "https://app.test/callback"))
  let assert Ok(Nil) = warden.start(client)
  // /login -> provider /authorize (signs "ada" in) -> /callback?code=...
  let assert Ok(redirect) =
    warden.begin_login(client, request.new(), warden.default_login())
  let assert Ok(callback) =
    testing.authorize(provider, redirect, subject: "ada")
  let assert Ok(session) = warden.complete_login(client, callback)
  assert warden.subject(warden.session_identity(session)) == "ada"
  // The next login at the provider's page is cancelled.
  testing.set_login(provider, testing.Refuse("access_denied"))
  warden.stop(client)
  testing.stop_provider(provider)
}
```

`warden/testing` runs a scripted provider over HTTPS on loopback with its own
PKI. A test browser follows the application's own `/login` redirect, trusting
`testing.trust_anchor_pem`, and returns to `/callback` with no test hook in the
application. `with_granted_scopes` and `with_email_claims` script per-subject
scopes and email assertions. Unit tests that hold a `LoginRedirect` call
`testing.authorize` and skip HTTP. The provider also mints and revokes tokens,
skews its clock, rotates its key and counts requests.

## Resource servers

Source: [`usage/resource_server.gleam`](consumer/src/warden_reference/usage/resource_server.gleam),
which also runs local validation, scope and audience refusals, and introspection
against revocation.

<!-- example: consumer/src/warden_reference/usage/resource_server.gleam resource-server -->

```gleam
pub fn start(
  issuer: String,
) -> Result(#(warden.Client, resource.Validator), warden.StartError) {
  let assert Ok(client) = warden.new(config.resource_server(issuer:))
  use Nil <- result.map(warden.start(client))
  #(client, resource.new(client, audience: "https://api.example.com"))
}

/// The HTTP status a failed token earns: 401, 403 or 503. A token issued for
/// another resource is answered as a rejected one here.
pub fn status(validator: resource.Validator, bearer: String) -> Int {
  case resource.verify(validator, bearer) {
    Ok(_claims) -> 200
    Error(error) ->
      case resource.error_kind(error) {
        resource.Rejected | resource.WrongAudience -> 401
        resource.Forbidden -> 403
        resource.Unavailable -> 503
      }
  }
}
```

[`warden/resource`](src/warden/resource.gleam) validates RFC 9068 JWT access tokens
with the issuer's cached keys. [`warden.introspect`](src/warden.gleam) checks the
provider's current token state for opaque tokens or immediate revocation. The
design's "Resource validation and provider operations" section states audience,
scope and availability failures.

The following Relay recipes leave required-scope admission to Relay and map
Warden's checked audience and failure evidence into caller-owned types.
`scripts/relay-recipe` compiles this block and compares it with the resource
module documentation.

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

## Oracles and benchmarks

[`docs/ORACLE.md`](docs/ORACLE.md) names the independent references Warden is
compared with (OpenID Foundation RP conformance suite, Keycloak, node-oidc-provider,
test-only oidcc), their pinned revisions, what each comparison establishes and how
to reproduce it. [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) retains local
measurements of provider cache cost, with their workloads, revisions and limits.
The two documents link to each other; neither result certifies a release.

## Development and design

```sh
nix develop -c scripts/check
```

The gate commands, provider suites and fresh-build sequence are in
[`AGENTS.md`](AGENTS.md). The [native design](docs/design/design.typ),
[vocabulary](docs/design/CONTEXT.typ) and [coverage map](docs/COVERAGE.md)
describe the full capability scope and unresolved requirements. The
[ADRs](docs/adr) record rationale and history.

## Optional PostgreSQL storage

[`warden_postgres`](integrations/warden_postgres/README.md) supplies the public
conditional-record store using a caller-owned Pog pool. Warden core does not
depend on it. Applications own schema initialization, pool lifetime, sealing keys,
capacity and backup protection; the adapter owns atomic writes.
