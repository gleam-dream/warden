//// Pending logins over a record store.
////
//// A login is one sealed record keyed by a digest of its `state`. `consume`
//// replaces the pending record with a consumed tombstone by compare-and-set
//// on the version read by `get`, so concurrent callbacks for one login see
//// exactly one `Consumed`. Expiry is decided from the material's own
//// `expires_at` at the moment of each decision. Tombstones stay until the
//// record expires (the login lifetime plus as much again), so a late or
//// losing callback reports replay or expiry rather than an unknown login.

import gleam/bit_array
import gleam/dynamic/decode
import gleam/json
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/time/timestamp
import warden/internal/port.{type Port}
import warden/internal/sealed.{type Keys}
import warden/store.{type StoreError, Record}

const kind = "warden.login.v1"

/// Immutable material for one login. Secret-bearing; it never leaves Warden.
pub type Material {
  Material(
    state: String,
    nonce: String,
    verifier: String,
    redirect_uri: String,
    browser_hash: String,
    max_age: Option(Int),
    created_at: Int,
    expires_at: Int,
  )
}

pub type Logins {
  Logins(port: Port, keys: Keys, clock: fn() -> Int, retention: Int)
}

pub type Lookup {
  Found(material: Material, version: Int)
  FoundConsumed
  FoundExpired
  NotFound
  /// The record did not open (tampered, or sealed with an unknown key).
  Unreadable
}

pub type Decision {
  Consumed(Material)
  AlreadyConsumed
  Expired
  Changed
  Missing
}

pub type PutError {
  PutFull
  PutFailed
}

type Stored {
  Pending(Material)
  Spent
}

pub fn put(
  logins: Logins,
  key: String,
  material: Material,
) -> Result(Nil, PutError) {
  let record =
    Record(
      key:,
      version: 1,
      expires_at: timestamp.from_unix_seconds(
        material.expires_at + logins.retention,
      ),
      sealed: seal(logins, key, 1, Pending(material)),
    )
  case port.put(logins.port, record, None) {
    Ok(True) -> Ok(Nil)
    // A state collision is not possible with 256 random bits; refuse.
    Ok(False) -> Error(PutFailed)
    Error(store.StoreFull) -> Error(PutFull)
    Error(_) -> Error(PutFailed)
  }
}

pub fn get(logins: Logins, key: String) -> Result(Lookup, StoreError) {
  use found <- result.map(port.get(logins.port, key))
  case found {
    None -> NotFound
    Some(record) ->
      case open(logins, key, record.version, record.sealed) {
        Error(Nil) -> Unreadable
        Ok(Spent) -> FoundConsumed
        Ok(Pending(material)) ->
          case logins.clock() < material.expires_at {
            True -> Found(material:, version: record.version)
            False -> FoundExpired
          }
      }
  }
}

/// Consume the login read at `version`. The clock is sampled for the
/// decision itself, after `get`.
pub fn consume(
  logins: Logins,
  key: String,
  material: Material,
  version: Int,
) -> Result(Decision, StoreError) {
  case logins.clock() < material.expires_at {
    False -> Ok(Expired)
    True -> {
      let record =
        Record(
          key:,
          version: version + 1,
          expires_at: timestamp.from_unix_seconds(
            material.expires_at + logins.retention,
          ),
          sealed: seal(logins, key, version + 1, Spent),
        )
      case port.put(logins.port, record, Some(version)) {
        Ok(True) -> Ok(Consumed(material))
        Ok(False) ->
          case get(logins, key) {
            Ok(FoundConsumed) -> Ok(AlreadyConsumed)
            Ok(FoundExpired) -> Ok(Expired)
            Ok(NotFound) -> Ok(Missing)
            Ok(_) -> Ok(Changed)
            Error(error) -> Error(error)
          }
        Error(error) -> Error(error)
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Sealed encoding

fn seal(logins: Logins, key: String, version: Int, value: Stored) -> BitArray {
  let body = case value {
    Spent -> json.object([#("spent", json.bool(True))])
    Pending(m) ->
      json.object([
        #("state", json.string(m.state)),
        #("nonce", json.string(m.nonce)),
        #("verifier", json.string(m.verifier)),
        #("redirect_uri", json.string(m.redirect_uri)),
        #("browser_hash", json.string(m.browser_hash)),
        #("max_age", json.nullable(m.max_age, json.int)),
        #("created_at", json.int(m.created_at)),
        #("expires_at", json.int(m.expires_at)),
      ])
  }
  sealed.seal(
    logins.keys,
    kind:,
    key:,
    version:,
    plaintext: bit_array.from_string(json.to_string(body)),
  )
}

fn open(
  logins: Logins,
  key: String,
  version: Int,
  value: BitArray,
) -> Result(Stored, Nil) {
  use plain <- result.try(sealed.open(
    logins.keys,
    kind:,
    key:,
    version:,
    sealed: value,
  ))
  use text <- result.try(bit_array.to_string(plain))
  json.parse(text, stored_decoder()) |> result.replace_error(Nil)
}

fn stored_decoder() -> decode.Decoder(Stored) {
  let pending = {
    use state <- decode.field("state", decode.string)
    use nonce <- decode.field("nonce", decode.string)
    use verifier <- decode.field("verifier", decode.string)
    use redirect_uri <- decode.field("redirect_uri", decode.string)
    use browser_hash <- decode.field("browser_hash", decode.string)
    use max_age <- decode.field("max_age", decode.optional(decode.int))
    use created_at <- decode.field("created_at", decode.int)
    use expires_at <- decode.field("expires_at", decode.int)
    decode.success(
      Pending(Material(
        state:,
        nonce:,
        verifier:,
        redirect_uri:,
        browser_hash:,
        max_age:,
        created_at:,
        expires_at:,
      )),
    )
  }
  let spent = {
    use _ <- decode.field("spent", decode.bool)
    decode.success(Spent)
  }
  decode.one_of(spent, [pending])
}
