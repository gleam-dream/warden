//// Local validation of JWT access tokens (RFC 9068), for resource servers.
////
//// A `Validator` checks a bearer token against the issuer's published keys,
//// using the started Warden client's key cache (an unknown `kid` refreshes
//// the keys once, throttled), so validation sends no request per token:
////
//// ```gleam
//// let assert Ok(client) = warden.new(config.resource_server(issuer:))
//// let assert Ok(Nil) = warden.start(client)
//// let validator = resource.new(client, audience: "https://api.example.com")
////
//// case resource.verify(validator, bearer_token) {
////   Ok(claims) -> resource.subject(claims)
////   Error(error) ->
////     case resource.error_kind(error) {
////       resource.Rejected -> todo    // 401, error="invalid_token"
////       resource.Forbidden -> todo   // 403, error="insufficient_scope"
////       resource.Unavailable -> todo // 503
////     }
//// }
//// ```
////
//// Every check fails closed:
////
//// | Check | Rule | Setter |
//// | --- | --- | --- |
//// | size | at most 8 KiB | |
//// | `alg` | in the configured allowlist; `none` and HMAC are never accepted | `with_algorithms` |
//// | `typ` | `at+jwt` (or `application/at+jwt`) | `allow_any_token_type` |
//// | signature | a key of the issuer's JWKS; the token's `kid` selects it | |
//// | `iss` | exactly the configured issuer | |
//// | `aud` | exactly `[audience]` | `with_audience_policy` |
//// | `exp` | required, strictly in the future | |
//// | `nbf`, `iat` | not later than now plus the clock tolerance; `iat` required | `config.with_clock_tolerance` |
//// | `sub` | required | |
//// | scopes | every required scope present | `with_required_scopes` |
////
//// Local validation cannot see revocation: a JWT access token stays valid
//// until `exp` even after the provider revoked it. A resource server that
//// must refuse a revoked token at once uses introspection
//// (`warden.introspect`, the second recipe below); otherwise keep access
//// tokens short-lived. `warden/testing.revoke_access_token` shows both
//// sides in a test.
////
//// ## With Relay
////
//// Relay's verifier takes a function from its `BearerToken` to an
//// attestation. `verifier` builds that function; Relay's `admit` then checks
//// the resource audience and the endpoint scopes itself, so leave
//// `with_required_scopes` unset. The recipe below, and the introspection
//// variant for opaque tokens or immediate revocation, is compiled against
//// Relay by `scripts/relay-recipe` on every gate run:
////
//// ```gleam
//// import gleam/option.{type Option, None, Some}
//// import relay/authorization.{type Attestation, type Verifier}
//// import warden
//// import warden/resource
////
//// pub type Principal {
////   Principal(subject: String, client_id: Option(String), scopes: List(String))
//// }
////
//// /// Local RFC 9068 validation: no provider request per token.
//// pub fn jwt_verifier(validator: resource.Validator) -> Verifier(Principal) {
////   authorization.verifier(
////     "warden-jwt",
////     resource.verifier(
////       validator,
////       authorization.token_value,
////       attest,
////       rejected: authorization.BearerRejected,
////       unavailable: authorization.VerifierUnavailable,
////     ),
////   )
//// }
////
//// fn attest(claims: resource.AccessClaims) -> Attestation(Principal) {
////   let scopes = resource.scopes(claims)
////   authorization.attestation(
////     Principal(resource.subject(claims), resource.client_id(claims), scopes),
////     resource.audiences(claims),
////     scopes,
////   )
//// }
////
//// /// RFC 7662 introspection: one provider request per token, so a revoked
//// /// token is refused at once.
//// pub fn introspection_verifier(client: warden.Client) -> Verifier(Principal) {
////   use token <- authorization.verifier("warden-introspection")
////   case warden.introspect(client, authorization.token_value(token)) {
////     Ok(warden.ActiveToken(warden.TokenInfo(subject: Some(subject), ..) as info)) ->
////       Ok(authorization.attestation(
////         Principal(subject, info.client_id, info.scopes),
////         info.audiences,
////         info.scopes,
////       ))
////     Ok(warden.ActiveToken(warden.TokenInfo(subject: None, ..))) ->
////       Error(authorization.VerifierUnmapped)
////     Ok(warden.InactiveToken) | Error(warden.IntrospectionTokenTooLarge) ->
////       Error(authorization.BearerRejected)
////     Error(warden.IntrospectionNotSupported)
////     | Error(warden.IntrospectionFailed(_)) ->
////       Error(authorization.VerifierUnavailable)
////   }
//// }
//// ```
////
//// Relay's `VerificationError` has no 403, so `verifier` folds a missing
//// scope into `BearerRejected` (401). Let Relay's `admit` report
//// insufficient scope (403) by leaving `with_required_scopes` unset.

import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/time/timestamp.{type Timestamp}
import warden.{type Client, type ProviderFailure}
import warden/config.{type SigningAlgorithm}
import warden/internal/native/client as native
import warden/internal/native/jose
import warden/internal/protocol
import warden/internal/redacted.{type Redacted}

/// The largest token `verify` accepts.
pub const max_token_bytes = 8192

/// How `aud` must name this resource server.
pub type AudiencePolicy {
  /// `aud` is exactly the configured audience: a token issued for several
  /// resource servers is refused, so one of them cannot replay it at
  /// another. The default.
  ExactAudience
  /// `aud` contains the configured audience among others.
  AudienceIncluded
}

/// A validator for one audience. Build it with `new` and the setters.
pub opaque type Validator {
  Validator(
    client: Client,
    audience: String,
    audience_policy: AudiencePolicy,
    algorithms: List(String),
    require_type: Bool,
    required_scopes: List(String),
  )
}

/// A validator for tokens issued by the client's issuer for `audience`.
/// The algorithm allowlist starts from the client's configured signing
/// algorithms (default RS256, PS256, ES256, EdDSA).
pub fn new(client: Client, audience audience: String) -> Validator {
  Validator(
    client:,
    audience:,
    audience_policy: ExactAudience,
    algorithms: client.settings.signing_algorithms,
    require_type: True,
    required_scopes: [],
  )
}

pub fn with_audience_policy(
  validator: Validator,
  policy: AudiencePolicy,
) -> Validator {
  Validator(..validator, audience_policy: policy)
}

/// The signing algorithms accepted. `none` and HMAC algorithms are not
/// representable, so a token cannot switch a public key into a shared
/// secret.
pub fn with_algorithms(
  validator: Validator,
  algorithms: List(SigningAlgorithm),
) -> Validator {
  Validator(..validator, algorithms: list.map(algorithms, algorithm_name))
}

/// Scopes every accepted token must carry (`scope`, space-separated, or a
/// `scp` list).
pub fn with_required_scopes(
  validator: Validator,
  scopes: List(String),
) -> Validator {
  Validator(..validator, required_scopes: scopes)
}

/// Accept tokens whose header `typ` is not `at+jwt`, for providers that do
/// not set it (RFC 9068 §4 requires the check). Prefer a provider setting
/// over this.
pub fn allow_any_token_type(validator: Validator) -> Validator {
  Validator(..validator, require_type: False)
}

/// Verified access-token claims. Built only by `verify`.
pub opaque type AccessClaims {
  AccessClaims(
    issuer: String,
    subject: String,
    client_id: Option(String),
    audiences: List(String),
    scopes: List(String),
    expires_at: Timestamp,
    issued_at: Timestamp,
    jwt_id: Option(String),
    claims: Redacted(Dynamic),
  )
}

pub fn issuer(claims: AccessClaims) -> String {
  claims.issuer
}

pub fn subject(claims: AccessClaims) -> String {
  claims.subject
}

/// `client_id` (RFC 9068), or `azp` when the provider uses that instead.
pub fn client_id(claims: AccessClaims) -> Option(String) {
  claims.client_id
}

pub fn audiences(claims: AccessClaims) -> List(String) {
  claims.audiences
}

pub fn scopes(claims: AccessClaims) -> List(String) {
  claims.scopes
}

pub fn expires_at(claims: AccessClaims) -> Timestamp {
  claims.expires_at
}

pub fn issued_at(claims: AccessClaims) -> Timestamp {
  claims.issued_at
}

pub fn jwt_id(claims: AccessClaims) -> Option(String) {
  claims.jwt_id
}

/// Decode the verified claims into a caller-owned type.
pub fn decode_claims(
  claims: AccessClaims,
  decoder: decode.Decoder(a),
) -> Result(a, List(decode.DecodeError)) {
  decode.run(redacted.reveal(claims.claims), decoder)
}

/// Why a token was not accepted. May gain variants; branch on
/// `error_kind`.
pub type TokenError {
  /// Empty, or longer than `max_token_bytes`.
  TokenTooLarge
  /// Not a compact JWS (an encrypted token is refused too).
  TokenMalformed
  /// The header `typ` is not `at+jwt`.
  TokenTypeInvalid
  /// `alg: none`.
  UnsignedToken
  /// `alg` is outside the allowlist (including any HMAC algorithm).
  AlgorithmNotAllowed
  /// No key of the issuer verifies this `kid`, even after refreshing keys.
  UnknownSigningKey
  BadSignature
  IssuerMismatch
  AudienceMismatch
  TokenExpired
  /// `nbf` or `iat` is in the future beyond the clock tolerance.
  TokenNotYetValid
  MissingClaim(String)
  /// The token is valid but lacks these required scopes.
  InsufficientScope(missing: List(String))
  /// The issuer's keys are not loaded or could not be fetched.
  KeysUnavailable(ProviderFailure)
}

/// How a resource server answers a token error (RFC 6750 §3.1).
pub type ErrorKind {
  /// 401 with `error="invalid_token"`.
  Rejected
  /// 403 with `error="insufficient_scope"`.
  Forbidden
  /// 503: the keys are unavailable; nothing about the token was decided.
  Unavailable
}

pub fn error_kind(error: TokenError) -> ErrorKind {
  case error {
    InsufficientScope(_) -> Forbidden
    KeysUnavailable(_) -> Unavailable
    _ -> Rejected
  }
}

pub fn describe_error(error: TokenError) -> String {
  case error {
    TokenTooLarge -> "the token is empty or larger than 8 KiB"
    TokenMalformed -> "the token is not a signed JWT"
    TokenTypeInvalid -> "the token type is not at+jwt"
    UnsignedToken -> "the token is unsigned (alg none)"
    AlgorithmNotAllowed -> "the token's algorithm is not allowed"
    UnknownSigningKey -> "no issuer key matches the token"
    BadSignature -> "the token's signature does not verify"
    IssuerMismatch -> "the token was issued by another issuer"
    AudienceMismatch -> "the token was issued for another audience"
    TokenExpired -> "the token expired"
    TokenNotYetValid -> "the token is not valid yet"
    MissingClaim(claim) -> "the token has no " <> claim <> " claim"
    InsufficientScope(missing) ->
      "the token lacks the scopes " <> string.join(missing, " ")
    KeysUnavailable(_) -> "the issuer's keys are unavailable"
  }
}

/// Verify a bearer token (the value after `Bearer `).
pub fn verify(
  validator: Validator,
  token: String,
) -> Result(AccessClaims, TokenError) {
  let size = string.byte_size(token)
  use _ <- result.try(case size == 0 || size > max_token_bytes {
    True -> Error(TokenTooLarge)
    False -> Ok(Nil)
  })
  let settings = validator.client.settings
  let expect =
    jose.AccessExpectations(
      issuer: settings.issuer,
      audience: validator.audience,
      exact_audience: validator.audience_policy == ExactAudience,
      algorithms: validator.algorithms,
      require_type: validator.require_type,
      now: timestamp.from_unix_seconds(settings.clock()),
      tolerance: settings.clock_tolerance_seconds,
    )
  use claims <- result.try(
    native.verify_access_token(validator.client.backend, token, expect)
    |> result.map_error(fn(error) {
      case error {
        Ok(rejection) -> token_error(rejection)
        Error(failure) -> KeysUnavailable(warden_failure(failure))
      }
    }),
  )
  let scopes = token_scopes(claims)
  use _ <- result.try(
    case
      list.filter(validator.required_scopes, fn(s) { !list.contains(scopes, s) })
    {
      [] -> Ok(Nil)
      missing -> Error(InsufficientScope(missing))
    },
  )
  let string_claim = fn(name) { protocol.string_claim(claims, name) }
  let time = fn(name) {
    protocol.int_claim(claims, name)
    |> option.map(timestamp.from_unix_seconds)
  }
  use expires_at <- result.try(option.to_result(
    time("exp"),
    MissingClaim("exp"),
  ))
  use issued_at <- result.try(option.to_result(time("iat"), MissingClaim("iat")))
  use subject <- result.try(option.to_result(
    string_claim("sub"),
    MissingClaim("sub"),
  ))
  Ok(AccessClaims(
    issuer: settings.issuer,
    subject:,
    client_id: case string_claim("client_id") {
      Some(id) -> Some(id)
      None -> string_claim("azp")
    },
    audiences: protocol.audiences(claims),
    scopes:,
    expires_at:,
    issued_at:,
    jwt_id: string_claim("jti"),
    claims: redacted.new(claims),
  ))
}

/// A verification function for a framework that hands its own token type
/// to a verifier (such as Relay's `authorization.verifier`): `token_value`
/// reads the raw token, `accept` builds the framework's result from the
/// claims, and failures map to `rejected` (every `Rejected` or `Forbidden`
/// error) or `unavailable`.
///
/// Two things to know:
///
/// - It folds 403 into 401. A token that lacks a `with_required_scopes` scope
///   is a `Forbidden` error, and the framework sees only `rejected`. Leave
///   `with_required_scopes` unset and let the framework check scopes (Relay's
///   `admit` answers 403), or call `verify` and `error_kind` yourself.
/// - `rejected` and `unavailable` have the same type, so swapping them
///   compiles and turns every bad token into 503 and every outage into 401.
///   Pass them by label, as in the module example, so a swap is visible.
pub fn verifier(
  validator: Validator,
  token_value: fn(token) -> String,
  accept: fn(AccessClaims) -> a,
  rejected rejected: e,
  unavailable unavailable: e,
) -> fn(token) -> Result(a, e) {
  fn(token) {
    case verify(validator, token_value(token)) {
      Ok(claims) -> Ok(accept(claims))
      Error(error) ->
        case error_kind(error) {
          Unavailable -> Error(unavailable)
          Rejected | Forbidden -> Error(rejected)
        }
    }
  }
}

fn token_scopes(claims: Dynamic) -> List(String) {
  let spaced =
    decode.at(["scope"], decode.string)
    |> decode.map(fn(s) {
      string.split(s, " ") |> list.filter(fn(x) { x != "" })
    })
  let listed = decode.at(["scope"], decode.list(decode.string))
  let scp = decode.at(["scp"], decode.list(decode.string))
  decode.run(claims, decode.one_of(spaced, [listed, scp]))
  |> result.unwrap([])
}

fn token_error(rejection: jose.Rejection) -> TokenError {
  case rejection.reason {
    "alg_none" -> UnsignedToken
    "unsupported_algorithm" -> AlgorithmNotAllowed
    "token_type" -> TokenTypeInvalid
    "unknown_key" -> UnknownSigningKey
    "bad_signature" -> BadSignature
    "issuer_mismatch" -> IssuerMismatch
    "audience_mismatch" -> AudienceMismatch
    "expired" -> TokenExpired
    "not_yet_valid" -> TokenNotYetValid
    "missing_claim" -> MissingClaim(option.unwrap(rejection.claim, "other"))
    _ -> TokenMalformed
  }
}

fn warden_failure(failure: protocol.Failure) -> ProviderFailure {
  case failure {
    protocol.NotReady -> warden.ProviderNotReady
    _ -> warden.UnclassifiedBackendFailure
  }
}

fn algorithm_name(algorithm: SigningAlgorithm) -> String {
  case algorithm {
    config.Rs256 -> "RS256"
    config.Rs384 -> "RS384"
    config.Rs512 -> "RS512"
    config.Ps256 -> "PS256"
    config.Ps384 -> "PS384"
    config.Ps512 -> "PS512"
    config.Es256 -> "ES256"
    config.Es384 -> "ES384"
    config.Es512 -> "ES512"
    config.EdDsa -> "EdDSA"
  }
}
