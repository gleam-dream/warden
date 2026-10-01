//// Consumer acceptance for Warden's public API: pure configuration of an
//// advanced client, caller-owned claim types and structured failure
//// handling. Provider journeys run in `browser/journey.mjs`.

import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleeunit
import warden
import warden/config
import warden_reference/web

pub fn main() -> Nil {
  gleeunit.main()
}

const es256_key = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"app-key-1\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}"

/// An advanced configuration: private_key_jwt, form-post responses, extra
/// scopes, a narrowed algorithm allowlist, a private-network provider with a
/// host allowlist and explicit trust, and a strict RFC 9207 policy.
pub fn advanced_configuration_validates_without_side_effects_test() {
  let assert Ok(key) = config.signing_key_from_jwk(es256_key)
  let settings =
    config.new(
      issuer: "https://login.internal.example",
      client_id: "reference",
      redirect_uri: "https://app.internal.example/callback",
      authentication: config.PrivateKeyJwt(key),
    )
    |> config.with_scopes(["email", "profile", "offline_access", "api:Read"])
    |> config.with_response_mode(config.FormPost)
    |> config.with_signing_algorithms([config.Es256, config.Ps256])
    |> config.with_issuer_parameter(config.AlwaysRequireIssuer)
    |> config.with_transport(config.Transport(
      trust: config.SystemTrust,
      destinations: config.AllowPrivateNetwork,
      allowed_hosts: Some(["login.internal.example"]),
      request_timeout_ms: 5000,
      max_response_bytes: 262_144,
    ))
    |> config.with_login_lifetime(300)
  let assert Ok(validated) = config.validate(settings)
  assert config.scopes(validated)
    == ["openid", "email", "profile", "offline_access", "api:Read"]
  assert config.signing_algorithms(validated) == ["ES256", "PS256"]
  assert config.authentication_method(validated) == "private_key_jwt"
}

pub fn invalid_configuration_reports_every_problem_test() {
  let assert Error(errors) =
    config.new(
      issuer: "http://login.example",
      client_id: "",
      redirect_uri: "http://app.example/callback",
      authentication: config.PublicClient,
    )
    |> config.with_scopes(["ok", "not ok"])
    |> config.validate
  assert list.contains(errors, config.InvalidIssuer)
  assert list.contains(errors, config.InvalidClientId)
  assert list.contains(errors, config.InvalidRedirectUri)
  assert list.contains(errors, config.InvalidScope("not ok"))
}

pub fn login_errors_map_to_application_failures_test() {
  assert web.login_failure(warden.LoginReplayed)
    == web.RetryLogin("this sign-in was already used")
  assert web.login_failure(warden.TransactionStoreUnavailable)
    == web.TryLater("sign-in store unavailable")
  let assert web.BadRequest(_) =
    web.login_failure(warden.CallbackRejected(warden.BrowserBindingMismatch))
  let assert web.RetryLogin(_) =
    web.login_failure(warden.IdentityRejected(warden.NonceMismatch))
}

pub fn caller_owned_claims_decode_test() {
  let claims =
    json.object([
      #("department", json.string("platform")),
      #("sub", json.string("s")),
    ])
    |> json.to_string
  let assert Ok(profile) = json.parse(claims, web.profile_decoder())
  assert profile == web.Profile(department: Some("platform"), locale: None)
  let assert Ok(_) = json.parse("{}", decode.success(Nil))
}
