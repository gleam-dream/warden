//// Usage: validate bearer tokens in a resource server.
////
//// `warden/resource` validates RFC 9068 JWT access tokens locally with the
//// issuer's cached keys: algorithm allowlist (`none` and HMAC cannot be
//// represented), `typ` `at+jwt`, exact `iss`, exact audience, strict `exp`,
//// `nbf` and `iat` within the clock tolerance, and required scopes.
//// `warden.introspect` (RFC 7662) is the alternative for opaque tokens or
//// immediate revocation. The Relay admission recipes for both are in the
//// README and compiled by `scripts/relay-recipe`.

import gleam/option.{Some}
import gleam/result
import warden
import warden/config
import warden/resource
import warden/testing

// snips-start: resource-server
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

// snips-end: resource-server

/// Local validation accepts and refuses by audience and scope; introspection
/// refuses a revoked access token at once, while a local validator accepts it
/// until it expires.
pub fn run() -> Nil {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  let audience = "https://api.example.com"
  let assert Ok(client) =
    warden.new(
      config.resource_server(issuer: testing.issuer(provider))
      |> testing.trusting(provider),
    )
  let assert Ok(Nil) = warden.start(client)
  let validator = resource.new(client, audience:)
  let token =
    testing.issue_access_token(
      provider,
      testing.access_token("ada")
        |> testing.with_audiences([audience])
        |> testing.with_scopes(["reports"]),
    )
  let assert Ok(claims) = resource.verify(validator, token)
  assert resource.subject(claims) == "ada"
  assert resource.scopes(claims) == ["reports"]
  assert status(validator, token) == 200
  // Another resource's token: a distinct kind, answered 401 above.
  let foreign =
    testing.issue_access_token(
      provider,
      testing.access_token("ada")
        |> testing.with_audiences(["https://other.example.com"]),
    )
  assert resource.verify(validator, foreign)
    |> result.map_error(resource.error_kind)
    == Error(resource.WrongAudience)
  assert status(validator, foreign) == 401
  // Required scopes: a valid token without them is a 403.
  let scoped = resource.with_required_scopes(validator, ["admin"])
  assert status(scoped, token) == 403
  // Introspection reflects revocation at once; local validation does not.
  let assert Ok(service) = warden.new(testing.service_config(provider))
  let assert Ok(Nil) = warden.start(service)
  let assert Ok(warden.ActiveToken(info)) = warden.introspect(service, token)
  assert info.subject == Some("ada")
  assert info.audiences == [audience]
  testing.revoke_access_token(provider, token)
  assert warden.introspect(service, token) == Ok(warden.InactiveToken)
  assert status(validator, token) == 200
  warden.stop(service)
  warden.stop(client)
  testing.stop_provider(provider)
}
