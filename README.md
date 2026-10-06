# warden

Warden signs users in with OpenID Connect, obtains OAuth 2.0 tokens and validates
JWT access tokens for Gleam applications on Erlang/OTP. It manages discovery,
signing keys and user-token storage; applications own their session cookies and
permission checks.

## Installation

This checkout is unreleased and pre-production. It requires Gleam 1.18 or later
and uses local path dependencies on HTTP Gun and Sinal. Place `warden`,
`http_gun` and `sinal` beside one another, then add Warden to your application's
`gleam.toml` (adjust the path for your directory layout):

```toml
[dependencies]
warden = { path = "../warden" }
```

Production use requires the [design's release conditions](docs/design/design.typ)
and independent security review of Warden-owned code. Warden is not certified;
[testing and evidence limits](docs/TESTING.md) describe what the retained checks
establish.

## Sign a user in, then call an API

Register the callback address with your issuer and supply the client secret from
trusted configuration. Create one client when the application starts and reuse
it across requests.

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

The example is compiled in
[`consumer/src/warden_reference/readme.gleam`](consumer/src/warden_reference/readme.gleam).
Its ordinary path runs against the local test provider in
[`common_path_test`](consumer/test/warden_reference_test.gleam).
The [reference application](consumer/) also supplies browser routes, application
session storage and route protection.

After the application stops admitting requests, call `warden.stop(client)` for
this manually started client. It waits up to five seconds for supervisor exit;
its return does not confirm every worker or external effect has finished. Keep
captured resources alive for the [completion boundary your application needs](docs/APPLICATION-RESPONSIBILITIES.md#resource-lifetime-and-observability).

## Defaults and failures

Sessions and pending logins use memory by default. A custody-store restart loses
sessions; use [durable stores and a sealing key](docs/USAGE.md#durable-sessions-and-several-nodes)
when sessions must survive it. A session lasts at most 12 hours, with a one-hour
idle lifetime. `access_token` refreshes within 30 seconds of expiry and concurrent
requests share one refresh.

Provider requests use verified HTTPS, public destinations and a ten-second
request deadline. Login requires advertised S256 PKCE and exact issuer, audience,
nonce and callback matching. See the [configuration defaults](docs/USAGE.md#defaults)
for limits and explicit overrides.

Use `login_error_action` and `session_error_action` for the closed caller actions:
`Reauthenticate`, `RetryLater`, `Recover`, `FixConfiguration` and `RejectRequest`.
A possibly sent authorization code or refresh token is never sent again. For
`Recover`, retain the full error and submit its carried value to `recover_custody`
or `recover_refresh`; recovery repeats storage publication without another
provider exchange. Log errors through the `describe_*` functions.

Keep the session reference in a protected application session. Use `(issuer,
subject)` as the identity key, and apply application permission and origin checks
on every protected route. The [application guide](docs/APPLICATION-RESPONSIBILITIES.md)
explains those decisions and the limits of record sealing.

## Resource servers

[`warden/resource`](src/warden/resource.gleam) validates RFC 9068 JWT access tokens
with the issuer's cached keys. [`warden.introspect`](src/warden.gleam) checks the
provider's current token state for opaque tokens or immediate revocation. The
[resource-server guide](docs/USAGE.md#resource-servers) shows configuration and
explains audience, scope and availability failures.

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

## Further use

- [Application supervision](docs/USAGE.md#under-supervision), including background discovery and restart behavior.
- [Several callback addresses](docs/USAGE.md#several-callback-addresses), selected by exact allowlist match.
- [Local HTTPS test providers](docs/USAGE.md#testing), including refusal, key rotation, scope changes and store checks.
- [Public modules](docs/USAGE.md#modules) for userinfo, service grants, custom claim decoding, storage and typed telemetry.

## Benchmarks

The [retained local measurements](docs/BENCHMARKS.md) recorded 2,528 token
validations/s for one client and 9,737/s across four concurrent clients after the
fetch-ownership change. These are medians from three warmed runs on OTP 28 with
four schedulers on 2026-10-05. The guide records workloads, revisions, cache-read
and large-key-set measurements, reproduction entry points and missing hardware
provenance; the results are not deployment capacity guarantees.

## Development and design

```sh
nix develop -c scripts/check
```

The fast gate checks formatting, build warnings, local tests, negative compiler
fixtures and both consumers. The [testing guide](docs/TESTING.md) lists the
separate local provider, browser and conformance suites.

The [native design](docs/design/design.typ), [rendered design](docs/design/design-layer.pdf),
[vocabulary](docs/design/CONTEXT.typ) and [coverage map](docs/COVERAGE.md) describe
the full capability scope and unresolved requirements. [ADRs](docs/adr/0010-native-documentation-ownership.md)
record rationale and history.
