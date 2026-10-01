//// Entropy, digests, constant-time comparison and time, on gleam_crypto
//// and gleam_time (OTP `crypto` underneath).

import gleam/bit_array
import gleam/crypto
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/erlang/atom
import gleam/list
import gleam/string
import gleam/time/timestamp

/// `bytes` bytes from the OS CSPRNG, base64url without padding.
pub fn random_token(bytes: Int) -> String {
  crypto.strong_random_bytes(bytes) |> bit_array.base64_url_encode(False)
}

/// RFC 7636 S256: BASE64URL(SHA256(ASCII(verifier))).
pub fn s256(verifier: String) -> String {
  crypto.hash(crypto.Sha256, <<verifier:utf8>>)
  |> bit_array.base64_url_encode(False)
}

pub fn sha256_hex(value: String) -> String {
  crypto.hash(crypto.Sha256, <<value:utf8>>)
  |> bit_array.base16_encode
  |> string.lowercase
}

/// Compares digests of both inputs, so timing does not depend on where the
/// inputs differ, including when their lengths differ.
pub fn constant_time_equal(a: String, b: String) -> Bool {
  let digest = fn(value: String) { crypto.hash(crypto.Sha256, <<value:utf8>>) }
  crypto.secure_compare(digest(a), digest(b))
  && string.byte_size(a) == string.byte_size(b)
}

pub fn now_seconds() -> Int {
  let #(seconds, _) =
    timestamp.system_time() |> timestamp.to_unix_seconds_and_nanoseconds
  seconds
}

/// Start the OTP applications the native backend needs (`crypto`,
/// `public_key`, `ssl`, `telemetry`); True when all are running.
pub fn ensure_applications() -> Bool {
  let names =
    list.map(["crypto", "public_key", "ssl", "telemetry"], atom.create)
  let ok = {
    use tag <- decode.field(0, atom.decoder())
    decode.success(atom.to_string(tag) == "ok")
  }
  decode.run(ensure_all_started(names), ok) == Ok(True)
}

@external(erlang, "application", "ensure_all_started")
fn ensure_all_started(applications: List(atom.Atom)) -> Dynamic

/// Monotonic seconds: for measuring lifetimes, never compared with Unix
/// time.
pub fn monotonic_seconds() -> Int {
  monotonic_time(atom.create("second"))
}

@external(erlang, "erlang", "monotonic_time")
fn monotonic_time(unit: atom.Atom) -> Int
