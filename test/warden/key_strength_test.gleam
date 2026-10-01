//// Key strength and purpose (internal security review, findings J1, C9):
//// RSA keys below 2048 bits (RFC 7518 §3.3) never verify ID tokens or sign
//// client assertions, and keys not meant for signing are refused at import.

import gleam/list
import gose/jose/key_set
import warden/config
import warden/internal/native/provider
import warden_test_support as support

fn key_count(jwks: List(String)) -> Int {
  let assert Ok(set) =
    provider.parse_key_set("{\"keys\":[" <> join(jwks) <> "]}")
  list.length(key_set.to_list(set))
}

fn join(items: List(String)) -> String {
  case items {
    [] -> ""
    [one] -> one
    [first, ..rest] -> first <> "," <> join(rest)
  }
}

pub fn weak_rsa_verification_keys_are_ignored_test() {
  assert key_count([support.rsa_jwk(1024, False)]) == 0
  assert key_count([support.rsa_jwk(2048, False)]) == 1
}

pub fn weak_rsa_signing_keys_are_rejected_test() {
  assert config.signing_key_from_jwk(support.rsa_jwk(1024, True))
    == Error(config.WeakRsaKey)
  let assert Ok(_) = config.signing_key_from_jwk(support.rsa_jwk(2048, True))
}

pub fn keys_not_meant_for_signing_are_rejected_test() {
  let key = support.client_private_jwk()
  assert config.signing_key_from_jwk(support.jwk_with(key, "use", "\"enc\""))
    == Error(config.NotForSigning)
  assert config.signing_key_from_jwk(support.jwk_with(
      key,
      "key_ops",
      "[\"verify\"]",
    ))
    == Error(config.NotForSigning)
  let assert Ok(_) =
    config.signing_key_from_jwk(support.jwk_with(key, "key_ops", "[\"sign\"]"))
  let assert Ok(_) =
    config.signing_key_from_jwk(support.jwk_with(key, "use", "\"sig\""))
}
