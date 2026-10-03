//// Entropy, digests, constant-time comparison and time, on gleam_crypto
//// and gleam_time (OTP `crypto` underneath).

import gleam/bit_array
import gleam/crypto
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/erlang/atom
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleam/time/timestamp
import gleam/uri

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

/// RFC 6749 §3.3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E ). Case is
/// preserved.
pub fn valid_scope(scope: String) -> Bool {
  let bytes = bit_array.from_string(scope)
  bit_array.byte_size(bytes) > 0 && scope_bytes_valid(bytes)
}

fn scope_bytes_valid(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> True
    <<byte, rest:bytes>> ->
      {
        byte == 0x21
        || { byte >= 0x23 && byte <= 0x5B }
        || { byte >= 0x5D && byte <= 0x7E }
      }
      && scope_bytes_valid(rest)
    _ -> False
  }
}

/// Redirect URIs must be absolute, fragment-free and `https`, except `http`
/// for loopback hosts (`127.0.0.1`, `[::1]`, `localhost`).
pub fn valid_redirect_uri(redirect: String) -> Bool {
  case uri.parse(redirect) {
    Ok(uri.Uri(
      scheme: Some(scheme),
      userinfo: None,
      host: Some(host),
      fragment: None,
      ..,
    )) ->
      host != ""
      && !string.contains(redirect, "#")
      && case scheme {
        "https" -> True
        "http" -> host == "127.0.0.1" || host == "::1" || host == "localhost"
        _ -> False
      }
    _ -> False
  }
}

/// Every byte is printable ASCII or above (no control characters).
pub fn printable(value: String) -> Bool {
  value
  |> bit_array.from_string
  |> all_bytes(fn(b) { b >= 0x20 && b != 0x7F })
}

/// True when every byte of `value` is a base64url character.
pub fn base64url_only(value: String) -> Bool {
  value
  |> bit_array.from_string
  |> all_bytes(fn(b) {
    { b >= 0x41 && b <= 0x5A }
    || { b >= 0x61 && b <= 0x7A }
    || { b >= 0x30 && b <= 0x39 }
    || b == 0x2D
    || b == 0x5F
  })
}

fn all_bytes(bytes: BitArray, check: fn(Int) -> Bool) -> Bool {
  case bytes {
    <<>> -> True
    <<b, rest:bytes>> -> check(b) && all_bytes(rest, check)
    _ -> False
  }
}

/// Monotonic milliseconds, for deadlines.
pub fn monotonic_ms() -> Int {
  monotonic_time(atom.create("millisecond"))
}
