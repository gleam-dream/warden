//// The README recipe, run through Relay's `admit` and `challenge` against
//// Warden's test provider: every refusal gets the challenge Relay owes it.

import gleam/option.{Some}
import gleam/string
import gleam/time/duration
import gleeunit
import recipe
import relay/authorization
import warden
import warden/config
import warden/testing

const resource_url = "https://mcp.example.test/mcp"

pub fn main() -> Nil {
  gleeunit.main()
}

fn started() -> #(testing.Provider, warden.Client) {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  let assert Ok(client) =
    warden.new(
      config.resource_server(issuer: testing.issuer(provider))
      |> testing.trusting(provider),
    )
  let assert Ok(Nil) = warden.start(client)
  #(provider, client)
}

fn protection() -> authorization.Protection {
  let assert Ok(resource) = authorization.protected_resource(resource_url)
  let assert Ok(read) = authorization.scope("read")
  authorization.protection(resource, [read])
}

fn spec() -> testing.TokenSpec {
  testing.access_token("ada")
  |> testing.with_audiences([resource_url])
  |> testing.with_scopes(["read"])
}

fn admit(provider: testing.Provider, client: warden.Client, spec) {
  let verifier = recipe.jwt_verifier(client, resource_url)
  let assert Ok(token) =
    authorization.bearer_token(testing.issue_access_token(provider, spec))
  authorization.admit(verifier, token, protection())
}

fn finish(provider: testing.Provider, client: warden.Client) -> Nil {
  warden.stop(client)
  testing.stop_provider(provider)
}

pub fn a_token_for_this_resource_is_admitted_test() {
  let #(provider, client) = started()
  let assert Ok(grant) = admit(provider, client, spec())
  assert authorization.grant_principal(grant).subject == "ada"
  finish(provider, client)
}

/// The wave 5 case: Warden used to refuse this token itself, so Relay only
/// ever saw `BearerRejected` and answered with the generic challenge.
pub fn a_token_for_another_resource_is_named_by_relay_test() {
  let #(provider, client) = started()
  let result =
    admit(
      provider,
      client,
      spec() |> testing.with_audiences(["https://other.example.test/mcp"]),
    )
  assert result == Error(authorization.ResourceNotGranted)
  let assert Error(error) = result
  let challenge = authorization.challenge(protection(), error)
  assert challenge.status == 401
  let assert Some(header) = challenge.www_authenticate
  assert string.contains(header, "invalid_token")
  assert string.contains(header, "issued for another resource")
  finish(provider, client)
}

pub fn a_token_for_two_resources_is_refused_by_relay_test() {
  let #(provider, client) = started()
  assert admit(
      provider,
      client,
      spec() |> testing.with_audiences([resource_url, "https://other.test"]),
    )
    == Error(authorization.ResourceNotGranted)
  finish(provider, client)
}

pub fn a_missing_scope_is_a_403_from_relay_test() {
  let #(provider, client) = started()
  let result = admit(provider, client, spec() |> testing.with_scopes([]))
  let assert Error(error) = result
  assert authorization.challenge(protection(), error).status == 403
  finish(provider, client)
}

/// Warden's other checks are untouched by the audience policy.
pub fn other_failures_stay_a_generic_401_test() {
  let #(provider, client) = started()
  let expired = spec() |> testing.with_ttl(duration.seconds(-10))
  assert admit(provider, client, expired)
    == Error(authorization.VerificationFailed(authorization.BearerRejected))
  let forged = spec() |> testing.forged(testing.UnsignedToken)
  assert admit(provider, client, forged)
    == Error(authorization.VerificationFailed(authorization.BearerRejected))
  finish(provider, client)
}
