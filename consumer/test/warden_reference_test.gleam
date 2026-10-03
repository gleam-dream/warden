//// Consumer acceptance for Warden's public API, from a separate package:
//// the common path end to end against `warden/testing`, an advanced
//// configuration, a caller-owned store adapter, caller-owned claim types,
//// resource-server validation with a framework-shaped verifier, and
//// structured failure handling. Browser journeys run in
//// `browser/journey.mjs`.

import gleam/crypto
import gleam/dynamic/decode
import gleam/http/request
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleam/time/duration
import gleeunit
import warden
import warden/config
import warden/resource
import warden/store
import warden/testing
import warden_reference/web

pub fn main() -> Nil {
  gleeunit.main()
}

const es256_key = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"app-key-1\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}"

/// The common path: configure, start, sign in, call an API with the token
/// (refreshed near expiry), sign out with revocation.
pub fn common_path_test() {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  let assert Ok(client) =
    warden.new(
      testing.config(provider, "https://app.test/callback")
      |> config.with_scopes(["email", "profile"]),
    )
  let assert Ok(Nil) = warden.start(client)
  // GET /login
  let assert Ok(redirect) =
    warden.begin_login(client, request.new(), warden.default_login())
  // The browser signs in at the provider and returns to the callback.
  let assert Ok(callback) =
    testing.authorize(provider, redirect, subject: "ada")
  // GET /callback
  let assert Ok(session) = warden.complete_login(client, callback)
  let reference = warden.session_reference(session)
  // Any later request.
  let assert Ok(session) = warden.restore_session(client, reference)
  let assert Ok(access) = warden.access_token(client, session)
  let api = warden.authorize(request.new(), access.token)
  assert request.get_header(api, "authorization")
    == Ok("Bearer " <> warden.access_token_value(access.token))
  let assert Ok(warden.LoggedOut(revocation: warden.Revoked, ..)) =
    warden.logout(client, access.session, warden.default_logout())
  assert warden.restore_session(client, reference)
    == Error(warden.SessionNotFound)
  warden.stop(client)
  testing.stop_provider(provider)
}

/// An advanced configuration: private_key_jwt, form-post responses, extra
/// scopes, a narrowed algorithm allowlist, a private-network provider with
/// a host allowlist, explicit bounds and a strict RFC 9207 policy.
pub fn advanced_configuration_validates_without_side_effects_test() {
  let assert Ok(key) = config.signing_key_from_jwk(es256_key)
  let configuration =
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
    |> config.with_destinations(config.AllowPrivateNetwork)
    |> config.with_allowed_hosts(["login.internal.example"])
    |> config.with_request_timeout(duration.seconds(5))
    |> config.with_max_response_bytes(262_144)
    |> config.with_login_lifetime(duration.minutes(5))
    |> config.with_refresh_margin(duration.minutes(1))
  assert config.validate(configuration) == Ok(Nil)
  let assert Ok(_client) = warden.new(configuration)
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
  assert list.all(errors, fn(e) { config.describe_config_error(e) != "" })
}

/// A caller-owned durable store: the adapter is three functions, checked
/// against the contract, and sessions in it are sealed.
pub fn caller_owned_store_adapter_test() {
  // Stands in for a database table; any compare-and-set store works.
  let table = testing.memory_store()
  let adapter =
    store.new(
      get: fn(key) { store.get(table, key) },
      put: fn(record, expected) { store.put(table, record, expected) },
      delete_expired: fn(now) { store.delete_expired(table, now) },
    )
  assert testing.check_store(adapter) == Ok(Nil)
  let assert Ok(sealing_key) =
    config.sealing_key(crypto.strong_random_bytes(32))
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  let assert Ok(client) =
    warden.new(
      testing.config(provider, "https://app.test/callback")
      |> config.with_custody_store(adapter)
      |> config.with_transaction_store(adapter)
      |> config.with_sealing_key(sealing_key),
    )
  let assert Ok(Nil) = warden.start(client)
  let assert Ok(redirect) =
    warden.begin_login(client, request.new(), warden.default_login())
  let assert Ok(callback) =
    testing.authorize(provider, redirect, subject: "ada")
  let assert Ok(session) = warden.complete_login(client, callback)
  // A second client on the same store and key (another node) restores it.
  let assert Ok(other) =
    warden.new(
      testing.config(provider, "https://app.test/callback")
      |> config.with_custody_store(adapter)
      |> config.with_sealing_key(sealing_key),
    )
  let assert Ok(Nil) = warden.start(other)
  let assert Ok(restored) =
    warden.restore_session(other, warden.session_reference(session))
  assert warden.subject(warden.session_identity(restored)) == "ada"
  warden.stop(other)
  warden.stop(client)
  testing.stop_provider(provider)
}

/// One client, two registered callback addresses: a login picks one from
/// the configured allowlist; any other URI fails closed.
pub fn login_chooses_a_registered_redirect_uri_test() {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  let admin = "https://admin.app.test/callback"
  let assert Ok(client) =
    warden.new(
      testing.config(provider, "https://app.test/callback")
      |> config.with_allowed_redirect_uris([admin]),
    )
  let assert Ok(Nil) = warden.start(client)
  let options = fn(uri) {
    warden.LoginOptions(..warden.default_login(), redirect_uri: Some(uri))
  }
  let assert Ok(redirect) =
    warden.begin_login(client, request.new(), options(admin))
  let assert Ok(callback) =
    testing.authorize(provider, redirect, subject: "ada")
  assert callback.host == "admin.app.test"
  let assert Ok(_) = warden.complete_login(client, callback)
  let assert Error(error) =
    warden.begin_login(client, request.new(), options(admin <> "/"))
  assert error == warden.InvalidLoginOption(warden.RedirectUriNotAllowed)
  assert warden.login_error_action(error) == warden.FixConfiguration
  warden.stop(client)
  testing.stop_provider(provider)
}

pub fn login_errors_map_to_application_failures_test() {
  let assert web.RetryLogin(_) = web.login_failure(warden.LoginReplayed)
  let assert web.BadRequest(_) =
    web.login_failure(warden.CallbackRejected(warden.BrowserBindingMismatch))
  let assert web.RetryLogin(_) =
    web.login_failure(warden.IdentityRejected(warden.NonceMismatch))
  let assert web.TryLater(_) = web.login_failure(warden.LoginStoreUnavailable)
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

/// A framework's own bearer type and attestation, as Relay's verifier
/// takes them: one line adapts the validator.
type Bearer {
  Bearer(String)
}

type Attestation {
  Attestation(subject: String, audiences: List(String), scopes: List(String))
}

type Refusal {
  BearerRejected
  VerifierUnavailable
}

fn bearer_value(bearer: Bearer) -> String {
  let Bearer(value) = bearer
  value
}

fn attest(claims: resource.AccessClaims) -> Attestation {
  Attestation(
    subject: resource.subject(claims),
    audiences: resource.audiences(claims),
    scopes: resource.scopes(claims),
  )
}

pub fn resource_server_validation_test() {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  let assert Ok(client) =
    warden.new(
      config.resource_server(issuer: testing.issuer(provider))
      |> testing.trusting(provider),
    )
  let assert Ok(Nil) = warden.start(client)
  let validator = resource.new(client, audience: "https://api.test")
  let verify =
    resource.verifier(
      validator,
      bearer_value,
      attest,
      BearerRejected,
      VerifierUnavailable,
    )
  let token =
    testing.issue_access_token(
      provider,
      testing.access_token("ada")
        |> testing.with_audiences(["https://api.test"])
        |> testing.with_scopes(["reports"]),
    )
  assert verify(Bearer(token))
    == Ok(Attestation("ada", ["https://api.test"], ["reports"]))
  let foreign =
    testing.issue_access_token(
      provider,
      testing.access_token("ada")
        |> testing.with_audiences(["https://other.test"]),
    )
  assert verify(Bearer(foreign)) == Error(BearerRejected)
  assert string.contains(
    resource.describe_error(resource.AudienceMismatch),
    "audience",
  )
  warden.stop(client)
  testing.stop_provider(provider)
}
