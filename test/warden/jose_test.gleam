//// ID-token and userinfo verification edge cases (internal security review,
//// findings J4, J5, J8, J13). Tokens are minted by erlang-jose, independent
//// of gose.

import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/time/timestamp
import warden/internal/native/jose
import warden/internal/native/provider
import warden_test_support as support

const issuer = "https://idp.example"

fn now() -> Int {
  support.now_seconds()
}

fn claims(overrides: List(#(String, json.Json))) -> String {
  let base = [
    #("iss", json.string(issuer)),
    #("aud", json.string("app")),
    #("sub", json.string("alice")),
    #("iat", json.int(now())),
    #("exp", json.int(now() + 300)),
    #("nonce", json.string("n")),
  ]
  let keys = list.map(overrides, fn(o) { o.0 })
  list.filter(base, fn(b) { !list.contains(keys, b.0) })
  |> list.append(overrides)
  |> list.filter(fn(c) { c.1 != json.null() })
  |> json.object
  |> json.to_string
}

fn expectations(access_token) -> jose.Expectations {
  jose.Expectations(
    issuer:,
    client_id: "app",
    algorithms: ["RS256", "EdDSA"],
    nonce: Some("n"),
    access_token:,
    now: timestamp.system_time(),
  )
}

fn verify(kind: String, header: String, claims: String, access_token) {
  let #(token, jwks) = support.mint(kind, header, claims)
  let assert Ok(keys) = provider.parse_key_set(jwks)
  jose.verify_id_token(token, keys, expectations(access_token))
}

fn reason(result: Result(a, jose.Rejection)) -> String {
  case result {
    Ok(_) -> "ok"
    Error(jose.Rejection(reason:, ..)) -> reason
  }
}

pub fn a_well_formed_token_verifies_test() {
  assert reason(verify("RS256", "{}", claims([]), None)) == "ok"
  assert reason(verify("Ed25519", "{}", claims([]), None)) == "ok"
}

/// A present claim of the wrong type is not "absent" (J4).
pub fn mistyped_azp_and_at_hash_are_rejected_test() {
  assert reason(verify("RS256", "{}", claims([#("azp", json.int(5))]), None))
    == "authorized_party_mismatch"
  assert reason(verify(
      "RS256",
      "{}",
      claims([#("at_hash", json.int(5))]),
      Some("access-token"),
    ))
    == "access_token_hash"
}

/// EdDSA means Ed25519 here; Ed448's at_hash would need SHAKE256 (J8).
pub fn ed448_keys_are_not_used_test() {
  assert reason(verify("Ed448", "{}", claims([]), None)) == "unknown_key"
}

/// `crit` must be a non-empty array when present (RFC 7515 §4.1.11, J13).
pub fn null_crit_header_is_rejected_test() {
  assert reason(verify("RS256", "{\"crit\":null}", claims([]), None))
    == "malformed"
}

/// Signed userinfo usually carries no `exp`; one that does is enforced (J5).
pub fn signed_userinfo_without_exp_verifies_test() {
  let userinfo = fn(overrides) {
    let #(token, jwks) =
      support.mint("RS256", "{}", claims([#("exp", json.null()), ..overrides]))
    let assert Ok(keys) = provider.parse_key_set(jwks)
    reason(jose.verify_userinfo(token, keys, expectations(None)))
  }
  assert userinfo([]) == "ok"
  assert userinfo([#("exp", json.int(now() - 10))]) == "expired"
}
