//// Local access-token validation (RFC 9068) against the public test
//// provider: every check fails closed.

import gleam/dynamic/decode
import gleam/option.{None, Some}
import gleam/otp/static_supervisor as supervisor
import gleam/time/duration
import warden
import warden/config
import warden/resource
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

pub fn relay_style_verifier_adapts_in_one_line_test() {
  let #(provider, client, validator) = started()
  let verify =
    resource.verifier(
      validator,
      fn(wrapped: #(String)) { wrapped.0 },
      resource.subject,
      "rejected",
      "unavailable",
    )
  let raw = testing.issue_access_token(provider, token(provider))
  assert verify(#(raw)) == Ok("ada")
  assert verify(#("garbage")) == Error("rejected")
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
  let assert Ok(_) =
    supervisor.new(supervisor.OneForOne)
    |> supervisor.add(warden.supervised(client))
    |> supervisor.start
  let validator = resource.new(client, audience:)
  let assert Error(error) = resource.verify(validator, token)
  assert error == resource.KeysUnavailable(warden.ProviderNotReady)
  assert resource.error_kind(error) == resource.Unavailable
  testing.stop_provider(provider)
}

/// `AudienceCheckedByCaller` skips only the `aud` comparison: the claims of
/// a token for another resource reach the caller with their real audiences,
/// and every other check still fails closed.
pub fn audience_checked_by_caller_skips_only_the_audience_test() {
  let #(provider, client, validator) = started()
  let deferred =
    resource.with_audience_policy(validator, resource.AudienceCheckedByCaller)
  let verify = fn(spec) {
    resource.verify(deferred, testing.issue_access_token(provider, spec))
  }
  let assert Ok(other) =
    verify(token(provider) |> testing.with_audiences(["https://other"]))
  assert resource.audiences(other) == ["https://other"]
  assert resource.subject(other) == "ada"
  let assert Ok(two) =
    verify(
      token(provider) |> testing.with_audiences([audience, "https://other"]),
    )
  assert resource.audiences(two) == [audience, "https://other"]
  // Everything else is unchanged.
  let wrong = testing.with_audiences(token(provider), ["https://other"])
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
  // The default policy still refuses the same token.
  assert resource.verify(validator, testing.issue_access_token(provider, wrong))
    == Error(resource.AudienceMismatch)
  stop(provider, client)
}

/// Behind a framework that compares audiences, the verifier hands it the
/// wrong resource instead of folding it into `rejected`.
pub fn verifier_reports_a_wrong_audience_when_the_caller_compares_test() {
  let #(provider, client, validator) = started()
  let deferred =
    resource.with_audience_policy(validator, resource.AudienceCheckedByCaller)
  let attest = fn(claims) { resource.audiences(claims) }
  let strict =
    resource.verifier(
      validator,
      fn(raw) { raw },
      attest,
      rejected: "rejected",
      unavailable: "unavailable",
    )
  let lenient =
    resource.verifier(
      deferred,
      fn(raw) { raw },
      attest,
      rejected: "rejected",
      unavailable: "unavailable",
    )
  let other =
    testing.issue_access_token(
      provider,
      token(provider) |> testing.with_audiences(["https://other"]),
    )
  assert strict(other) == Error("rejected")
  assert lenient(other) == Ok(["https://other"])
  let expired =
    testing.issue_access_token(
      provider,
      token(provider) |> testing.with_ttl(duration.seconds(-10)),
    )
  assert lenient(expired) == Error("rejected")
  stop(provider, client)
}
