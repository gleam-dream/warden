//// Pure and boundary unit tests: configuration validation and defaults,
//// callback parsing, PKCE derivation, entropy shape and total decoding of
//// foreign terms.

import gleam/bit_array
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleam/time/duration
import warden
import warden/config
import warden/internal/callback
import warden/internal/secure
import warden/internal/settings
import warden/testing
import warden_test_support as support

// --- RFC 7636 Appendix B -----------------------------------------------------

pub fn rfc7636_appendix_b_vector_test() {
  assert secure.s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
    == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
}

pub fn entropy_shape_test() {
  let tokens =
    list.map(list.repeat(Nil, 200), fn(_) { secure.random_token(32) })
  assert list.all(tokens, fn(t) { string.length(t) == 43 })
  assert list.length(list.unique(tokens)) == 200
  assert list.all(tokens, secure.base64url_only)
}

pub fn constant_time_equal_test() {
  assert secure.constant_time_equal("abc", "abc")
  assert !secure.constant_time_equal("abc", "abd")
  assert !secure.constant_time_equal("abc", "abcd")
  assert !secure.constant_time_equal("", "a")
}

// --- Configuration -------------------------------------------------------------

fn base() -> config.Config {
  config.new(
    issuer: "https://idp.example",
    client_id: "app",
    redirect_uri: "https://app.example/cb",
    authentication: config.ClientSecretBasic(config.secret("s")),
  )
}

fn errors(config: config.Config) -> List(config.ConfigError) {
  case config.validate(config) {
    Ok(Nil) -> []
    Error(errors) -> errors
  }
}

/// The defaults are decision 5's numbers.
pub fn defaults_match_the_release_table_test() {
  let c = base()
  assert c.request_timeout_ms == 10_000
  assert c.max_response_bytes == 1_048_576
  assert c.startup_timeout_ms == 15_000
  assert c.store_timeout_ms == 5000
  assert c.login_timeout_ms == 30_000
  assert c.login_lifetime_seconds == 600
  assert c.max_pending_logins == 100_000
  assert c.session_absolute_seconds == 43_200
  assert c.session_idle_seconds == 3600
  assert c.clock_tolerance_seconds == 5
  assert c.refresh_margin_seconds == 30
  assert c.refresh_wait_ms == 5000
  assert c.signing_algorithms == ["RS256", "PS256", "ES256", "EdDSA"]
  assert c.destinations == settings.PublicOnly
  assert c.trust == settings.SystemTrust
  assert c.custody_store == None
  assert c.transaction_store == None
  assert !c.assume_s256
  assert config.validate(c) == Ok(Nil)
}

pub fn durations_set_the_bounds_test() {
  let c =
    base()
    |> config.with_request_timeout(duration.seconds(3))
    |> config.with_startup_timeout(duration.seconds(4))
    |> config.with_store_timeout(duration.milliseconds(250))
    |> config.with_login_timeout(duration.seconds(20))
    |> config.with_login_lifetime(duration.minutes(5))
    |> config.with_session_lifetime(
      absolute: duration.hours(2),
      idle: duration.minutes(30),
    )
    |> config.with_clock_tolerance(duration.seconds(0))
    |> config.with_refresh_margin(duration.minutes(1))
    |> config.with_refresh_wait(duration.seconds(2))
  assert c.request_timeout_ms == 3000
  assert c.startup_timeout_ms == 4000
  assert c.store_timeout_ms == 250
  assert c.login_timeout_ms == 20_000
  assert c.login_lifetime_seconds == 300
  assert c.session_absolute_seconds == 7200
  assert c.session_idle_seconds == 1800
  assert c.clock_tolerance_seconds == 0
  assert c.refresh_margin_seconds == 60
  assert c.refresh_wait_ms == 2000
  assert config.validate(c) == Ok(Nil)
}

pub fn limits_name_their_setter_test() {
  let invalid = [
    #(
      base() |> config.with_request_timeout(duration.seconds(0)),
      config.RequestTimeout,
      "with_request_timeout",
    ),
    #(
      base() |> config.with_login_lifetime(duration.seconds(0)),
      config.LoginLifetime,
      "with_login_lifetime",
    ),
    #(
      base() |> config.with_clock_tolerance(duration.seconds(301)),
      config.ClockTolerance,
      "with_clock_tolerance",
    ),
    #(
      base() |> config.with_refresh_wait(duration.minutes(2)),
      config.RefreshWait,
      "with_refresh_wait",
    ),
    #(
      base() |> config.with_max_pending_logins(0),
      config.MaxPendingLogins,
      "with_max_pending_logins",
    ),
    #(
      base() |> config.with_max_response_bytes(10),
      config.MaxResponseBytes,
      "with_max_response_bytes",
    ),
    #(
      base() |> config.with_login_timeout(duration.minutes(11)),
      config.LoginTimeout,
      "with_login_timeout",
    ),
  ]
  list.each(invalid, fn(c) {
    assert errors(c.0) == [config.InvalidLimit(c.1)]
    assert string.contains(
      config.describe_config_error(config.InvalidLimit(c.1)),
      c.2,
    )
  })
}

pub fn issuer_validation_test() {
  let check = fn(issuer) {
    !list.contains(
      errors(settings.Settings(..base(), issuer:)),
      config.InvalidIssuer,
    )
  }
  assert check("https://idp.example")
  assert check("https://idp.example/realms/x")
  assert !check("http://idp.example")
  assert !check("https://idp.example?x=1")
  assert !check("https://idp.example#f")
  assert !check("https://user@idp.example")
  assert !check("idp.example")
  assert !check("")
}

pub fn redirect_uri_policy_test() {
  assert secure.valid_redirect_uri("https://app.example/cb")
  assert secure.valid_redirect_uri("http://127.0.0.1:8080/cb")
  assert secure.valid_redirect_uri("http://localhost/cb")
  assert secure.valid_redirect_uri("http://[::1]:9/cb")
  assert !secure.valid_redirect_uri("http://app.example/cb")
  assert !secure.valid_redirect_uri("https://app.example/cb#frag")
  assert !secure.valid_redirect_uri("javascript:alert(1)")
  assert !secure.valid_redirect_uri("/relative")
  assert !secure.valid_redirect_uri("custom:/cb")
  assert errors(config.new(
      issuer: "https://idp.example",
      client_id: "app",
      redirect_uri: "http://app.example/cb",
      authentication: config.PublicClient,
    ))
    == [config.InvalidRedirectUri]
}

pub fn scope_syntax_preserves_case_test() {
  assert secure.valid_scope("Read:Items")
  assert secure.valid_scope("https://api.example/x")
  assert !secure.valid_scope("")
  assert !secure.valid_scope("a b")
  assert !secure.valid_scope("quote\"")
  assert !secure.valid_scope("back\\slash")
  assert !secure.valid_scope("caf\u{e9}")
  assert !secure.valid_scope("tab\t")
  assert errors(config.with_scopes(base(), ["ok", "bad scope"]))
    == [config.InvalidScope("bad scope")]
}

pub fn openid_scope_is_implicit_test() {
  let c = config.with_scopes(base(), ["email", "openid", "email"])
  assert c.scopes == ["email"]
}

pub fn algorithms_are_required_test() {
  assert errors(config.with_signing_algorithms(base(), []))
    == [config.NoSigningAlgorithms]
}

pub fn trust_anchors_must_parse_test() {
  assert errors(config.with_trust(base(), config.TrustAnchorsPem("not pem")))
    == [config.InvalidTrustAnchors]
}

pub fn unadvertised_pkce_requires_a_confidential_client_test() {
  let public =
    config.new(
      issuer: "https://idp.example",
      client_id: "app",
      redirect_uri: "https://app.example/cb",
      authentication: config.PublicClient,
    )
  let assume = fn(c) {
    config.with_pkce_advertisement(c, config.AssumeS256WhenUnadvertised)
  }
  assert errors(assume(public))
    == [config.UnadvertisedPkceRequiresConfidentialClient]
  assert errors(assume(base())) == []
  assert errors(public) == []
}

pub fn service_client_needs_credentials_and_no_redirect_test() {
  let service =
    config.service_client(
      issuer: "https://idp.example",
      client_id: "svc",
      authentication: config.ClientSecretBasic(config.secret("s")),
    )
  assert errors(service) == []
  assert service.redirect_uri == ""
  assert errors(config.service_client(
      issuer: "https://idp.example",
      client_id: "svc",
      authentication: config.PublicClient,
    ))
    == [config.ServiceClientNeedsCredentials]
  assert errors(config.resource_server(issuer: "https://idp.example")) == []
}

pub fn durable_stores_need_a_sealing_key_test() {
  let store = testing.memory_store()
  assert errors(config.with_custody_store(base(), store))
    == [config.SealingKeyRequired]
  assert errors(config.with_transaction_store(base(), store))
    == [config.SealingKeyRequired]
  let assert Ok(key) = config.sealing_key(<<0:256>>)
  assert errors(
      base()
      |> config.with_custody_store(store)
      |> config.with_sealing_key(key),
    )
    == []
  assert config.sealing_key(<<0:128>>) == Error(config.SealingKeyNot32Bytes)
  // The key does not print.
  let raw = <<"SENTINEL-SEALING-KEY-32-BYTES!!!":utf8>>
  assert bit_array.byte_size(raw) == 32
  let assert Ok(secret) = config.sealing_key(raw)
  assert !string.contains(
    string.inspect(config.with_sealing_key(base(), secret)),
    "SENTINEL",
  )
}

pub fn secrets_do_not_appear_in_inspection_test() {
  let c =
    config.new(
      issuer: "https://idp.example",
      client_id: "app",
      redirect_uri: "https://app.example/cb",
      authentication: config.ClientSecretPost(config.secret("SENTINEL-SECRET")),
    )
  assert !string.contains(string.inspect(c), "SENTINEL-SECRET")
  let assert Ok(client) = warden.new(c)
  assert !string.contains(string.inspect(client), "SENTINEL-SECRET")
}

pub fn invalid_configuration_is_a_start_error_test() {
  let assert Error(warden.InvalidConfig([config.InvalidIssuer]) as error) =
    warden.new(settings.Settings(..base(), issuer: "http://idp"))
  assert string.contains(warden.describe_start_error(error), "issuer")
}

pub fn private_jwk_is_required_for_private_key_jwt_test() {
  assert config.signing_key_from_jwk("{}")
    == Error(config.NotAPrivateSigningJwk)
  assert config.signing_key_from_jwk("not json")
    == Error(config.NotAPrivateSigningJwk)
  // A public key cannot sign.
  let public =
    "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}"
  assert config.signing_key_from_jwk(public)
    == Error(config.NotAPrivateSigningJwk)
  let private =
    "{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"k1\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}"
  let assert Ok(key) = config.signing_key_from_jwk(private)
  assert !string.contains(string.inspect(key), "jpsQnnGQ")
}

// --- Callback parsing ----------------------------------------------------------

pub fn callback_parsing_table_test() {
  let parse = fn(raw) { callback.parse(raw, False) }
  assert parse("code=c&state=s")
    == Ok(callback.CodeResponse(state: "s", code: "c", issuer: None))
  assert parse("code=c&state=s&iss=https%3A%2F%2Fidp")
    == Ok(callback.CodeResponse(
      state: "s",
      code: "c",
      issuer: Some("https://idp"),
    ))
  assert parse("error=access_denied&state=s")
    == Ok(callback.ErrorResponse(
      state: "s",
      error: "access_denied",
      issuer: None,
    ))
  assert parse("code=c&state=s&state=t") == Error(callback.DuplicateParameter)
  assert parse("code=c&code=c&state=s") == Error(callback.DuplicateParameter)
  assert parse("code=c&error=x&state=s") == Error(callback.AmbiguousResponse)
  assert parse("code=&state=s") == Error(callback.EmptyCode)
  assert parse("state=s") == Error(callback.MissingCode)
  assert parse("code=c") == Error(callback.MissingState)
  assert parse("code=c&state=") == Error(callback.MissingState)
  assert parse("code=c&state=s&iss=") == Error(callback.InvalidParameterValue)
  assert parse("code=%0A&state=s") == Error(callback.InvalidParameterValue)
  assert parse("code=c&state=%ZZ") == Error(callback.InvalidEncoding)
  assert parse("error=bad%22quote&state=s")
    == Error(callback.InvalidParameterValue)
  assert parse(string.repeat("x", callback.max_input_bytes + 1))
    == Error(callback.InputTooLarge)
  // Both the query and the form body are application/x-www-form-urlencoded
  // (RFC 6749 Appendix B), where '+' is a space (review finding F8).
  assert callback.parse("code=a+b&state=s", True)
    == Ok(callback.CodeResponse(state: "s", code: "a b", issuer: None))
  assert callback.parse("code=a+b&state=s", False)
    == Ok(callback.CodeResponse(state: "s", code: "a b", issuer: None))
  // A '%' that does not start an escape is invalid encoding.
  assert parse("code=%&state=s") == Error(callback.InvalidEncoding)
  assert parse("code=a%2&state=s") == Error(callback.InvalidEncoding)
  // `error` is NQSCHAR, which excludes the space.
  assert parse("error=access%20denied&state=s")
    == Error(callback.InvalidParameterValue)
}

@external(erlang, "warden_unit_ffi", "random_query")
fn random_query(seed: Int) -> String

/// Random inputs never crash the parser and never yield a response without a
/// non-empty state.
pub fn callback_parser_is_total_test() {
  list.repeat(Nil, 3000)
  |> list.index_map(fn(_, i) { i + 1 })
  |> list.each(fn(seed) {
    let raw = random_query(seed)
    case callback.parse(raw, seed % 2 == 0) {
      Ok(callback.CodeResponse(state:, code:, ..)) -> {
        assert state != ""
        assert code != ""
      }
      Ok(callback.ErrorResponse(state:, ..)) -> {
        assert state != ""
      }
      Error(_) -> Nil
    }
  })
}

// --- Internal security review: configuration (C10, C12, J7) -------------------

pub fn trust_anchors_must_all_be_certificates_test() {
  // A CERTIFICATE block whose content is not a certificate.
  let bogus = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
  assert errors(config.with_trust(base(), config.TrustAnchorsPem(bogus)))
    == [config.InvalidTrustAnchors]
  // A private key bundled with a valid anchor is refused, not ignored.
  let bundle = support.ca_pem() <> support.pki_file("localhost.key")
  assert errors(config.with_trust(base(), config.TrustAnchorsPem(bundle)))
    == [config.InvalidTrustAnchors]
  assert errors(config.with_trust(
      base(),
      config.TrustAnchorsPem(support.ca_pem()),
    ))
    == []
}

pub fn client_secrets_must_be_usable_test() {
  let with = fn(authentication) {
    errors(config.new(
      issuer: "https://idp.example",
      client_id: "app",
      redirect_uri: "https://app.example/cb",
      authentication:,
    ))
  }
  assert with(config.ClientSecretBasic(config.secret("")))
    == [config.EmptyClientSecret]
  assert with(config.ClientSecretPost(config.secret("")))
    == [config.EmptyClientSecret]
  // HS256 needs a key of at least 32 bytes (RFC 7518 §3.2).
  assert with(config.ClientSecretJwt(config.secret(string.repeat("k", 31))))
    == [config.ClientSecretTooShort]
  assert with(config.ClientSecretJwt(config.secret(string.repeat("k", 32))))
    == []
}

pub fn jwt_secret_length_limits_the_hmac_algorithms_test() {
  let algorithms = fn(length) {
    config.new(
      issuer: "https://idp.example",
      client_id: "app",
      redirect_uri: "https://app.example/cb",
      authentication: config.ClientSecretJwt(
        config.secret(string.repeat("k", length)),
      ),
    )
    |> settings.assertion_algorithms
  }
  assert algorithms(32) == ["HS256"]
  assert algorithms(48) == ["HS256", "HS384"]
  assert algorithms(64) == ["HS256", "HS384", "HS512"]
}

// --- Session lifetime (review finding F2) ------------------------------------

pub fn session_lifetime_validation_test() {
  let lifetime = fn(absolute, idle) {
    errors(config.with_session_lifetime(
      base(),
      absolute: duration.seconds(absolute),
      idle: duration.seconds(idle),
    ))
  }
  assert lifetime(600, 60) == []
  assert lifetime(60, 600) == [config.InvalidLimit(config.SessionLifetime)]
  assert lifetime(600, 0) == [config.InvalidLimit(config.SessionLifetime)]
}
