//// Key policy applied to JSON Web Keys before gose parses them, for both
//// provider verification keys and the client's own signing key.
////
//// - RSA keys below 2048 bits are refused (RFC 7518 §3.3); a smaller modulus
////   can be factored, which would let anyone forge signatures with it.
//// - EdDSA keys must be Ed25519.
//// - A signing key must permit signing: `use`, when present, is `sig`, and
////   `key_ops`, when present, includes `sign`.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/list
import gleam/result

pub const minimum_rsa_bits = 2048

/// False for an RSA key whose modulus is below `minimum_rsa_bits` or cannot
/// be read; True for every other key type.
pub fn strong_enough(fields: Dict(String, Dynamic)) -> Bool {
  case member(fields, "kty", decode.string) {
    Ok("RSA") ->
      case member(fields, "n", decode.string) |> result.try(modulus_bits) {
        Ok(bits) -> bits >= minimum_rsa_bits
        Error(Nil) -> False
      }
    _ -> True
  }
}

/// False for key types Warden does not use for EdDSA: only Ed25519 is
/// supported (its `at_hash` uses SHA-512; Ed448 would need SHAKE256).
pub fn supported_curve(fields: Dict(String, Dynamic)) -> Bool {
  case member(fields, "kty", decode.string) {
    Ok("OKP") -> member(fields, "crv", decode.string) == Ok("Ed25519")
    _ -> True
  }
}

/// True when the key's declared purpose permits signing.
pub fn for_signing(fields: Dict(String, Dynamic)) -> Bool {
  let use_ok = case dict.has_key(fields, "use") {
    False -> True
    True -> member(fields, "use", decode.string) == Ok("sig")
  }
  let ops_ok = case dict.has_key(fields, "key_ops") {
    False -> True
    True ->
      case member(fields, "key_ops", decode.list(decode.string)) {
        Ok(ops) -> list.contains(ops, "sign")
        Error(Nil) -> False
      }
  }
  use_ok && ops_ok
}

fn member(
  fields: Dict(String, Dynamic),
  name: String,
  decoder: decode.Decoder(a),
) -> Result(a, Nil) {
  use value <- result.try(dict.get(fields, name))
  decode.run(value, decoder) |> result.replace_error(Nil)
}

/// Bit length of a base64url-encoded unsigned big-endian integer.
fn modulus_bits(encoded: String) -> Result(Int, Nil) {
  use bytes <- result.try(bit_array.base64_url_decode(encoded))
  case strip_leading_zeros(bytes) {
    <<first, rest:bytes>> ->
      Ok(bit_array.byte_size(rest) * 8 + significant_bits(first, 0))
    _ -> Error(Nil)
  }
}

fn strip_leading_zeros(bytes: BitArray) -> BitArray {
  case bytes {
    <<0, rest:bytes>> -> strip_leading_zeros(rest)
    _ -> bytes
  }
}

fn significant_bits(byte: Int, bits: Int) -> Int {
  case byte {
    0 -> bits
    _ -> significant_bits(byte / 2, bits + 1)
  }
}
