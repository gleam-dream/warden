//// Pure and boundary unit tests: configuration validation, callback
//// parsing, PKCE derivation, entropy shape and total decoding of foreign
//// terms.

import gleam/list
import gleam/option.{None, Some}
import gleam/string
import warden
import warden/config
import warden/internal/callback
import warden/internal/secure

// --- RFC 7636 Appendix B -----------------------------------------------------

fn s256(verifier: String) -> String {
  secure.s256(verifier)
}

fn random_token(bytes: Int) -> String {
  secure.random_token(bytes)
}

fn constant_time_equal(a: String, b: String) -> Bool {
  secure.constant_time_equal(a, b)
}

pub fn rfc7636_appendix_b_vector_test() {
  assert s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
    == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
}

pub fn entropy_shape_test() {
  let tokens = list.map(list.repeat(Nil, 200), fn(_) { random_token(32) })
  assert list.all(tokens, fn(t) { string.length(t) == 43 })
  assert list.length(list.unique(tokens)) == 200
  assert list.all(tokens, fn(t) {
    warden.parse_browser_binding(t) |> option.from_result |> option.is_some
  })
}

pub fn constant_time_equal_test() {
  assert constant_time_equal("abc", "abc")
  assert !constant_time_equal("abc", "abd")
  assert !constant_time_equal("abc", "abcd")
  assert !constant_time_equal("", "a")
}

pub fn browser_binding_parsing_test() {
  assert warden.parse_browser_binding("short") == Error(Nil)
  assert warden.parse_browser_binding(string.repeat("a", 42) <> "!")
    == Error(Nil)
  let assert Ok(b) = warden.parse_browser_binding(string.repeat("A", 43))
  assert warden.browser_binding_value(b) == string.repeat("A", 43)
}

// --- Configuration -------------------------------------------------------------

fn base() -> config.Settings {
  config.new(
    issuer: "https://idp.example",
    client_id: "app",
    redirect_uri: "https://app.example/cb",
    authentication: config.ClientSecretBasic(config.secret("s")),
  )
}

pub fn issuer_validation_test() {
  let check = fn(issuer) {
    case config.validate(config.Settings(..base(), issuer:)) {
      Ok(_) -> True
      Error(errors) -> !list.contains(errors, config.InvalidIssuer)
    }
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
  assert config.valid_redirect_uri("https://app.example/cb")
  assert config.valid_redirect_uri("http://127.0.0.1:8080/cb")
  assert config.valid_redirect_uri("http://localhost/cb")
  assert config.valid_redirect_uri("http://[::1]:9/cb")
  assert !config.valid_redirect_uri("http://app.example/cb")
  assert !config.valid_redirect_uri("https://app.example/cb#frag")
  assert !config.valid_redirect_uri("javascript:alert(1)")
  assert !config.valid_redirect_uri("/relative")
  assert !config.valid_redirect_uri("custom:/cb")
}

pub fn scope_syntax_preserves_case_test() {
  assert config.valid_scope("Read:Items")
  assert config.valid_scope("https://api.example/x")
  assert !config.valid_scope("")
  assert !config.valid_scope("a b")
  assert !config.valid_scope("quote\"")
  assert !config.valid_scope("back\\slash")
  assert !config.valid_scope("caf\u{e9}")
  assert !config.valid_scope("tab\t")
  let assert Error(errors) =
    config.validate(config.with_scopes(base(), ["ok", "bad scope"]))
  assert errors == [config.InvalidScope("bad scope")]
}

pub fn openid_scope_is_always_first_test() {
  let assert Ok(validated) =
    config.validate(config.with_scopes(base(), ["email", "openid", "email"]))
  assert config.scopes(validated) == ["openid", "email"]
}

pub fn limits_and_algorithms_are_validated_test() {
  let assert Error(errors) =
    config.validate(
      config.Settings(
        ..base(),
        login_lifetime_seconds: 0,
        signing_algorithms: [],
      ),
    )
  assert list.contains(errors, config.NoSigningAlgorithms)
  assert list.contains(errors, config.InvalidLimit("login_lifetime_seconds"))
}

pub fn trust_anchors_must_parse_test() {
  let assert Error([config.InvalidTrustAnchors]) =
    config.validate(config.with_trust(base(), config.TrustAnchorsPem("not pem")))
}

pub fn secrets_do_not_appear_in_inspection_test() {
  let settings =
    config.new(
      issuer: "https://idp.example",
      client_id: "app",
      redirect_uri: "https://app.example/cb",
      authentication: config.ClientSecretPost(config.secret("SENTINEL-SECRET")),
    )
  assert !string.contains(string.inspect(settings), "SENTINEL-SECRET")
  let assert Ok(validated) = config.validate(settings)
  assert !string.contains(string.inspect(validated), "SENTINEL-SECRET")
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
  // Form encoding turns '+' into a space; query encoding keeps it.
  assert callback.parse("code=a+b&state=s", True)
    == Ok(callback.CodeResponse(state: "s", code: "a b", issuer: None))
  assert callback.parse("code=a+b&state=s", False)
    == Ok(callback.CodeResponse(state: "s", code: "a+b", issuer: None))
}

@external(erlang, "crypto", "strong_rand_bytes")
fn random_bytes(n: Int) -> BitArray

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
  let _ = random_bytes(1)
  Nil
}
