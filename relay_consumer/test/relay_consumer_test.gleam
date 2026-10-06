//// The README recipe, run through Relay's `admit` and `challenge` against
//// Warden's test provider: every refusal gets the challenge Relay owes it.

import gleam/erlang/process
import gleam/list
import gleam/option.{Some}
import gleam/string
import gleam/time/duration
import gleeunit
import recipe
import relay/authorization
import sinal
import sinal/correlation
import warden
import warden/config
import warden/resource
import warden/telemetry
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
  let verifier =
    recipe.jwt_verifier(resource.new(client, audience: resource_url))
  let assert Ok(token) =
    authorization.bearer_token(testing.issue_access_token(provider, spec))
  authorization.admit(verifier, token, protection(), correlation.unique())
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

/// A checked token for another resource gets Relay's specific challenge.
pub fn a_token_for_another_resource_is_named_by_relay_test() {
  let #(provider, client) = started()
  let result =
    admit(
      provider,
      client,
      spec() |> testing.with_audiences(["https://other.example.test/mcp"]),
    )
  assert result
    == Error(authorization.VerificationFailed(
      authorization.IssuedForAnotherResource,
    ))
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
    == Error(authorization.VerificationFailed(
      authorization.IssuedForAnotherResource,
    ))
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

/// The request's correlation tags the introspection call, so the provider
/// request joins the MCP request in telemetry.
pub fn introspection_carries_the_request_correlation_test() {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  let assert Ok(client) =
    warden.new(testing.config(provider, "https://app.example.test/callback"))
  let assert Ok(Nil) = warden.start(client)
  let assert Ok(issued) = warden.client_credentials(client, ["read"])
  let assert Ok(token) =
    authorization.bearer_token(warden.access_token_value(issued.access_token))
  let request = correlation.from_key("mcp-request-7")
  let inbox = process.new_subject()
  let plan =
    sinal.subscriptions([
      sinal.subscription(telemetry.http_request(), fn(_, event) {
        process.send(inbox, #(event.path, event.correlation))
      }),
    ])
  let assert Ok(_) =
    sinal.with_subscriptions(plan, fn() {
      authorization.admit(
        recipe.introspection_verifier(client),
        token,
        protection(),
        request,
      )
    })
  let events = drain(inbox, [])
  assert list.any(events, fn(event) { string.contains(event.0, "introspect") })
  assert list.all(events, fn(event) { event.1 == Some(request) })
  finish(provider, client)
}

fn drain(inbox, acc) {
  case process.receive(inbox, 0) {
    Ok(item) -> drain(inbox, [item, ..acc])
    Error(Nil) -> list.reverse(acc)
  }
}
