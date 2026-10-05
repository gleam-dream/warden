//// Local access-token validation (RFC 9068) against the public test
//// provider: every check fails closed.

import exception
import gleam/dynamic/decode
import gleam/erlang/atom
import gleam/erlang/process
import gleam/option.{None, Some}
import gleam/otp/actor
import gleam/otp/static_supervisor as supervisor
import gleam/time/duration
import sinal
import warden
import warden/config
import warden/resource
import warden/telemetry
import warden/testing

const audience = "https://api.example.test"

fn started() -> #(testing.Provider, warden.Client, resource.Validator) {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  let assert Ok(client) =
    warden.new(
      config.resource_server(issuer: testing.issuer(provider))
      |> testing.trusting(provider),
    )
  let assert Ok(Nil) = warden.start(client)
  #(provider, client, resource.new(client, audience:))
}

fn token(provider: testing.Provider) -> testing.TokenSpec {
  let _ = provider
  testing.access_token("ada")
  |> testing.with_audiences([audience])
  |> testing.with_scopes(["read", "write"])
}

fn stop(provider: testing.Provider, client: warden.Client) -> Nil {
  warden.stop(client)
  testing.stop_provider(provider)
}

pub fn valid_token_yields_typed_claims_test() {
  let #(provider, client, validator) = started()
  let raw = testing.issue_access_token(provider, token(provider))
  let assert Ok(claims) = resource.verify(validator, raw)
  assert resource.subject(claims) == "ada"
  assert resource.issuer(claims) == testing.issuer(provider)
  assert resource.audiences(claims) == [audience]
  assert resource.scopes(claims) == ["read", "write"]
  assert resource.client_id(claims) == Some(testing.client_id(provider))
  assert option.is_some(resource.jwt_id(claims))
  let assert Ok("ada") =
    resource.decode_claims(claims, decode.at(["sub"], decode.string))
  stop(provider, client)
}

pub fn every_rejection_is_typed_test() {
  let #(provider, client, validator) = started()
  let verify = fn(spec) {
    resource.verify(validator, testing.issue_access_token(provider, spec))
  }
  assert verify(token(provider) |> testing.with_ttl(duration.seconds(-10)))
    == Error(resource.TokenExpired)
  assert verify(token(provider) |> testing.with_audiences(["https://other"]))
    == Error(resource.AudienceMismatch)
  // Exact audience by default: a token for two resource servers is refused.
  assert verify(
      token(provider) |> testing.with_audiences([audience, "https://other"]),
    )
    == Error(resource.AudienceMismatch)
  assert verify(token(provider) |> testing.with_issuer("https://evil.test"))
    == Error(resource.IssuerMismatch)
  assert verify(token(provider) |> testing.forged(testing.UnsignedToken))
    == Error(resource.UnsignedToken)
  assert verify(token(provider) |> testing.forged(testing.HmacWithPublicKey))
    == Error(resource.AlgorithmNotAllowed)
  assert verify(token(provider) |> testing.forged(testing.UnknownKey))
    == Error(resource.UnknownSigningKey)
  assert verify(token(provider) |> testing.with_token_type(Some("JWT")))
    == Error(resource.TokenTypeInvalid)
  assert verify(token(provider) |> testing.with_token_type(None))
    == Error(resource.TokenTypeInvalid)
  assert resource.verify(validator, "") == Error(resource.TokenTooLarge)
  assert resource.verify(validator, "not.a.jwt")
    == Error(resource.TokenMalformed)
  assert resource.error_kind(resource.TokenExpired) == resource.Rejected
  stop(provider, client)
}

pub fn audience_policy_and_type_can_be_relaxed_explicitly_test() {
  let #(provider, client, validator) = started()
  let two =
    testing.issue_access_token(
      provider,
      token(provider) |> testing.with_audiences([audience, "https://other"]),
    )
  let assert Ok(_) =
    resource.verify(
      resource.with_audience_policy(validator, resource.AudienceIncluded),
      two,
    )
  let untyped =
    testing.issue_access_token(
      provider,
      token(provider) |> testing.with_token_type(Some("JWT")),
    )
  let assert Ok(_) =
    resource.verify(resource.allow_any_token_type(validator), untyped)
  stop(provider, client)
}

pub fn required_scopes_are_forbidden_not_rejected_test() {
  let #(provider, client, validator) = started()
  let raw = testing.issue_access_token(provider, token(provider))
  let strict = resource.with_required_scopes(validator, ["read", "admin"])
  let assert Error(resource.InsufficientScope(missing: ["admin"]) as error) =
    resource.verify(strict, raw)
  assert resource.error_kind(error) == resource.Forbidden
  stop(provider, client)
}

pub fn rotated_key_is_fetched_once_test() {
  let #(provider, client, validator) = started()
  let before = testing.requests(provider).keys
  testing.rotate_signing_key(provider)
  let raw = testing.issue_access_token(provider, token(provider))
  let assert Ok(_) = resource.verify(validator, raw)
  let assert Ok(_) = resource.verify(validator, raw)
  assert testing.requests(provider).keys == before + 1
  stop(provider, client)
}

pub fn algorithm_allowlist_is_enforced_test() {
  let #(provider, client, validator) = started()
  let raw = testing.issue_access_token(provider, token(provider))
  let rsa_only = resource.with_algorithms(validator, [config.Rs256])
  assert resource.verify(rsa_only, raw) == Error(resource.AlgorithmNotAllowed)
  stop(provider, client)
}

pub fn relay_style_verifier_maps_every_kind_test() {
  let #(provider, client, validator) = started()
  let verify =
    resource.verifier(
      resource.with_required_scopes(validator, ["admin"]),
      fn(wrapped: #(String)) { wrapped.0 },
      resource.subject,
      on_error: fn(kind) {
        case kind {
          resource.Rejected -> "rejected"
          resource.WrongAudience -> "wrong audience"
          resource.Forbidden -> "forbidden"
          resource.Unavailable -> "unavailable"
        }
      },
    )
  let issue = fn(spec) { #(testing.issue_access_token(provider, spec)) }
  let admin = token(provider) |> testing.with_scopes(["admin"])
  assert verify(issue(admin)) == Ok("ada")
  assert verify(#("garbage")) == Error("rejected")
  assert verify(issue(token(provider))) == Error("forbidden")
  assert verify(issue(testing.with_audiences(admin, ["https://other"])))
    == Error("wrong audience")
  stop(provider, client)
}

/// Without loaded keys nothing about the token is decided: the error is
/// `Unavailable` (503), not a rejection.
pub fn keys_unavailable_is_not_a_rejection_test() {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  let token =
    testing.issue_access_token(
      provider,
      testing.access_token("ada") |> testing.with_audiences([audience]),
    )
  // A client whose issuer is not reachable: supervised, it never discovers.
  let assert Ok(client) =
    warden.new(
      config.resource_server(issuer: "https://localhost:1")
      |> config.with_destinations(config.AllowLoopbackForTesting),
    )
  let discovery = process.new_subject()
  let observer =
    sinal.observe(telemetry.http_request(), fn(_, event) {
      case event.path, event.outcome {
        "/.well-known/openid-configuration",
          telemetry.Failed(telemetry.NotSent, telemetry.ConnectionRefused)
        -> process.send(discovery, process.self())
        _, _ -> Nil
      }
    })
  use <- exception.defer(fn() {
    let assert Ok(Nil) = sinal.detach(observer)
  })
  let assert Ok(actor.Started(pid: supervisor, ..)) =
    supervisor.new(supervisor.OneForOne)
    |> supervisor.add(warden.supervised(client))
    |> supervisor.start
  // Stop the owning supervisor; stopping only its client would restart it.
  use <- exception.defer(fn() {
    let monitor = process.monitor(supervisor)
    process.unlink(supervisor)
    process.send_abnormal_exit(supervisor, atom.create("shutdown"))
    let assert Ok(_) =
      process.new_selector()
      |> process.select_specific_monitor(monitor, fn(down) { down })
      |> process.selector_receive(5000)
    assert process.named(client.names.supervisor) == Error(Nil)
  })
  // Settle the observed discovery attempt before stopping its owning tree.
  let assert Ok(worker) = process.receive(discovery, 5000)
  let monitor = process.monitor(worker)
  let assert Ok(_) =
    process.new_selector()
    |> process.select_specific_monitor(monitor, fn(down) { down })
    |> process.selector_receive(5000)
  let validator = resource.new(client, audience:)
  let assert Error(error) = resource.verify(validator, token)
  assert error == resource.KeysUnavailable(warden.ProviderNotReady)
  assert resource.error_kind(error) == resource.Unavailable
  testing.stop_provider(provider)
}

/// `AudienceMismatch` means everything else passed: the token is valid but
/// names another resource. Any other fault comes first.
pub fn a_wrong_audience_is_reported_only_for_an_otherwise_valid_token_test() {
  let #(provider, client, validator) = started()
  let verify = fn(spec) {
    resource.verify(validator, testing.issue_access_token(provider, spec))
  }
  let wrong = testing.with_audiences(token(provider), ["https://other"])
  assert verify(wrong) == Error(resource.AudienceMismatch)
  assert resource.error_kind(resource.AudienceMismatch)
    == resource.WrongAudience
  assert verify(wrong |> testing.with_ttl(duration.seconds(-10)))
    == Error(resource.TokenExpired)
  assert verify(wrong |> testing.with_issuer("https://evil.test"))
    == Error(resource.IssuerMismatch)
  assert verify(wrong |> testing.forged(testing.UnsignedToken))
    == Error(resource.UnsignedToken)
  assert verify(wrong |> testing.forged(testing.HmacWithPublicKey))
    == Error(resource.AlgorithmNotAllowed)
  assert verify(wrong |> testing.forged(testing.UnknownKey))
    == Error(resource.UnknownSigningKey)
  assert verify(wrong |> testing.with_token_type(None))
    == Error(resource.TokenTypeInvalid)
  stop(provider, client)
}
