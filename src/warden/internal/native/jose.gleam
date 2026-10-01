//// JWT verification and client assertions for the native backend, on gose.
////
//// Verification order for an ID token:
//// 1. refuse encrypted tokens (Warden supports no ID-token decryption);
//// 2. read the protected header's `alg`; refuse `none` and any algorithm
////    outside the configured allowlist before touching keys;
//// 3. select keys compatible with that algorithm (gose pins the algorithm
////    per verifier, so HMAC confusion with a public key cannot happen);
//// 4. verify the signature and `iss`, `aud`, `exp`, `nbf` with gose;
//// 5. apply OpenID rules gose does not own: audience exactly the client,
////    `azp` equal to the client when present, required `sub` and `iat`,
////    nonce, and `at_hash` when present.
//// Results use the closed reason codes of `protocol.IdTokenInvalid`.

import gleam/bit_array
import gleam/crypto
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/time/duration
import gleam/time/timestamp.{type Timestamp}
import gose
import gose/jose/jwk
import gose/jose/jwt
import gose/jose/key_set.{type JwkSet}
import warden/internal/protocol

pub type Expectations {
  Expectations(
    issuer: String,
    client_id: String,
    algorithms: List(String),
    nonce: Option(String),
    access_token: Option(String),
    now: Timestamp,
  )
}

/// A verification failure: the closed reason and, for missing claims, the
/// claim name.
pub type Rejection {
  Rejection(reason: String, claim: Option(String))
}

fn reject(reason: String) -> Result(a, Rejection) {
  Error(Rejection(reason:, claim: None))
}

fn missing(claim: String) -> Result(a, Rejection) {
  Error(Rejection(reason: "missing_claim", claim: Some(claim)))
}

/// Verify an ID token and return its claims as a JSON-shaped term.
pub fn verify_id_token(
  token: String,
  keys: JwkSet,
  expect: Expectations,
) -> Result(Dynamic, Rejection) {
  use verified <- result.try(verify_signed(
    token,
    keys,
    expect,
    Some(expect.issuer),
    Some(expect.client_id),
  ))
  use claims <- result.try(
    jwt.decode(verified, decode.dynamic)
    |> result.replace_error(Rejection("malformed", None)),
  )
  use _ <- result.try(case protocol.audiences(claims) {
    [audience] if audience == expect.client_id -> Ok(Nil)
    _ -> reject("audience_mismatch")
  })
  use _ <- result.try(case protocol.string_claim(claims, "azp") {
    None -> Ok(Nil)
    Some(azp) if azp == expect.client_id -> Ok(Nil)
    Some(_) -> reject("authorized_party_mismatch")
  })
  use _ <- result.try(case protocol.string_claim(claims, "sub") {
    Some(sub) if sub != "" -> Ok(Nil)
    _ -> missing("sub")
  })
  use _ <- result.try(case protocol.int_claim(claims, "iat") {
    Some(_) -> Ok(Nil)
    None -> missing("iat")
  })
  use _ <- result.try(case expect.nonce {
    None -> Ok(Nil)
    Some(nonce) ->
      case protocol.string_claim(claims, "nonce") {
        Some(found) ->
          case crypto.secure_compare(<<found:utf8>>, <<nonce:utf8>>) {
            True -> Ok(Nil)
            False -> reject("nonce_mismatch")
          }
        None -> reject("nonce_mismatch")
      }
  })
  use _ <- result.try(
    case protocol.string_claim(claims, "at_hash"), expect.access_token {
      Some(expected), Some(access_token) ->
        case token_hash(jwt_alg(verified), access_token) == Ok(expected) {
          True -> Ok(Nil)
          False -> reject("access_token_hash")
        }
      _, _ -> Ok(Nil)
    },
  )
  Ok(claims)
}

/// Verify a signed userinfo response. `iss` and `aud` are checked when the
/// token carries them; the subject is checked by the caller.
pub fn verify_userinfo(
  token: String,
  keys: JwkSet,
  expect: Expectations,
) -> Result(Dynamic, Rejection) {
  use verified <- result.try(verify_signed(token, keys, expect, None, None))
  use claims <- result.try(
    jwt.decode(verified, decode.dynamic)
    |> result.replace_error(Rejection("malformed", None)),
  )
  use _ <- result.try(case protocol.string_claim(claims, "iss") {
    Some(iss) if iss != expect.issuer -> reject("issuer_mismatch")
    _ -> Ok(Nil)
  })
  case protocol.audiences(claims) {
    [] -> Ok(claims)
    audiences ->
      case list.contains(audiences, expect.client_id) {
        True -> Ok(claims)
        False -> reject("audience_mismatch")
      }
  }
}

fn verify_signed(
  token: String,
  keys: JwkSet,
  expect: Expectations,
  issuer: Option(String),
  audience: Option(String),
) -> Result(jwt.Jwt(jwt.Verified), Rejection) {
  use header <- result.try(protected_header(token))
  use _ <- result.try(case header.alg {
    "none" -> reject("alg_none")
    alg ->
      case list.contains(expect.algorithms, alg) {
        True -> Ok(Nil)
        False -> reject("unsupported_algorithm")
      }
  })
  use parsed <- result.try(
    jwt.parse(token) |> result.replace_error(Rejection("malformed", None)),
  )
  let alg = jwt.alg(parsed)
  let options =
    jwt.JwtValidationOptions(
      ..jwt.default_validation(),
      issuer:,
      audience:,
      clock_skew: 0,
      require_exp: True,
    )
  let compatible =
    key_set.to_list(keys)
    |> list.filter(fn(key) {
      result.is_ok(jwt.verifier(alg, keys: [key], options:))
    })
  // A token naming a kid is checked against that key, or against keys
  // without a kid; never against keys with a different kid.
  let candidates = case header.kid {
    Some(kid) ->
      case list.filter(compatible, fn(key) { gose.kid(key) == Ok(kid) }) {
        [] -> list.filter(compatible, fn(key) { gose.kid(key) == Error(Nil) })
        matching -> matching
      }
    None -> compatible
  }
  case candidates {
    [] -> reject("unknown_key")
    _ -> {
      use verifier <- result.try(
        jwt.verifier(alg, keys: candidates, options:)
        |> result.replace_error(Rejection("unknown_key", None)),
      )
      jwt.verify_and_validate(verifier, token:, now: expect.now)
      |> result.map_error(rejection)
    }
  }
}

fn rejection(error: jwt.JwtError) -> Rejection {
  case error {
    jwt.InvalidSignature -> Rejection("bad_signature", None)
    jwt.TokenExpired(..) -> Rejection("expired", None)
    jwt.TokenNotYetValid(..) | jwt.IssuedInFuture(..) ->
      Rejection("not_yet_valid", None)
    jwt.MissingExpiration -> Rejection("missing_claim", Some("exp"))
    jwt.MissingIssuedAt -> Rejection("missing_claim", Some("iat"))
    jwt.IssuerMismatch(..) -> Rejection("issuer_mismatch", None)
    jwt.AudienceMismatch(..) -> Rejection("audience_mismatch", None)
    jwt.JwsAlgorithmMismatch(..) -> Rejection("unsupported_algorithm", None)
    jwt.MissingKid | jwt.UnknownKid(..) -> Rejection("unknown_key", None)
    _ -> Rejection("malformed", None)
  }
}

type Header {
  Header(alg: String, kid: Option(String))
}

/// The JOSE protected header of a compact token. A five-part token is a JWE;
/// Warden decrypts no ID tokens.
fn protected_header(token: String) -> Result(Header, Rejection) {
  case string.split(token, ".") {
    [_, _, _, _, _] -> reject("encrypted_unsupported")
    [header, _, _] ->
      bit_array.base64_url_decode(header)
      |> result.try(bit_array.to_string)
      |> result.try(fn(text) {
        json.parse(text, {
          use alg <- decode.field("alg", decode.string)
          use kid <- decode.optional_field(
            "kid",
            None,
            decode.optional(decode.string),
          )
          decode.success(Header(alg:, kid:))
        })
        |> result.replace_error(Nil)
      })
      |> result.replace_error(Rejection("malformed", None))
    _ -> reject("malformed")
  }
}

fn jwt_alg(token: jwt.Jwt(jwt.Verified)) -> gose.SigningAlg {
  jwt.alg(token)
}

/// OIDC Core §3.1.3.6: left half of the hash of the access token, with the
/// hash of the ID token's algorithm (SHA-512 for Ed25519).
fn token_hash(
  alg: gose.SigningAlg,
  access_token: String,
) -> Result(String, Nil) {
  use hash <- result.try(case alg {
    gose.DigitalSignature(gose.RsaPkcs1(gose.RsaPkcs1Sha256))
    | gose.DigitalSignature(gose.RsaPss(gose.RsaPssSha256))
    | gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256)) -> Ok(crypto.Sha256)
    gose.DigitalSignature(gose.RsaPkcs1(gose.RsaPkcs1Sha384))
    | gose.DigitalSignature(gose.RsaPss(gose.RsaPssSha384))
    | gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP384)) -> Ok(crypto.Sha384)
    gose.DigitalSignature(gose.RsaPkcs1(gose.RsaPkcs1Sha512))
    | gose.DigitalSignature(gose.RsaPss(gose.RsaPssSha512))
    | gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP521))
    | gose.DigitalSignature(gose.Eddsa) -> Ok(crypto.Sha512)
    _ -> Error(Nil)
  })
  let digest = crypto.hash(hash, <<access_token:utf8>>)
  let half = bit_array.byte_size(digest) / 2
  use left <- result.map(bit_array.slice(digest, 0, half))
  bit_array.base64_url_encode(left, False)
}

// ---------------------------------------------------------------------------
// Client assertions (RFC 7523, OIDC Core §9)

pub type AssertionKey {
  SecretKey(secret: String)
  PrivateJwk(json: String)
}

/// Sign a client assertion with the first configured algorithm the provider
/// also supports (any, when the provider lists none).
pub fn client_assertion(
  key: AssertionKey,
  client_id: String,
  audience: String,
  algorithms: List(String),
  provider_algorithms: List(String),
  jti: String,
  now: Timestamp,
) -> Result(String, Nil) {
  let usable = case provider_algorithms {
    [] -> algorithms
    advertised -> list.filter(algorithms, list.contains(advertised, _))
  }
  use name <- result.try(list.first(list.filter(usable, fn(a) { a != "none" })))
  use alg <- result.try(signing_alg(name))
  use signing_key <- result.try(case key {
    SecretKey(secret) ->
      gose.from_octet_bits(<<secret:utf8>>) |> result.replace_error(Nil)
    PrivateJwk(text) -> jwk.from_json(text) |> result.replace_error(Nil)
  })
  let claims =
    jwt.claims()
    |> jwt.with_issuer(client_id)
    |> jwt.with_subject(client_id)
    |> jwt.with_audience(audience)
    |> jwt.with_jwt_id(jti)
    |> jwt.with_issued_at(now)
    |> jwt.with_expiration(timestamp.add(now, duration.seconds(60)))
  jwt.sign(alg, claims:, key: signing_key)
  |> result.map(jwt.serialize)
  |> result.replace_error(Nil)
}

fn signing_alg(name: String) -> Result(gose.SigningAlg, Nil) {
  case jwk.alg_from_string(name) {
    Ok(gose.SigningAlg(alg)) -> Ok(alg)
    _ -> Error(Nil)
  }
}

/// The `kid` of a compact JWS, if any (used to request a key refresh).
pub fn token_kid(token: String) -> Option(String) {
  case protected_header(token) {
    Ok(header) -> header.kid
    Error(_) -> None
  }
}
