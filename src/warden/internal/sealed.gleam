//// Sealing of stored records with AES-256-GCM (OTP `crypto` through
//// kryptos).
////
//// A sealed value is `<<1, key_id:8 bytes, nonce:12 bytes, tag:16 bytes,
//// ciphertext>>`. The nonce is random per seal. The additional data binds the
//// record kind, its store key and its version, so a sealed value moved to
//// another key or version does not open: a database writer cannot forge a
//// session, swap two sessions or replay one record under another key. It can
//// still restore an earlier row of the same key in full (rollback); see
//// decision D21.
////
//// `key_id` is a digest prefix of the key, so a key ring with retired keys
//// opens records sealed before a rotation.

import gleam/bit_array
import gleam/crypto
import gleam/list
import gleam/result
import kryptos/aead
import kryptos/block
import warden/internal/redacted.{type Redacted}

pub opaque type Keys {
  Keys(current: Key, previous: List(Key))
}

type Key {
  Key(id: BitArray, secret: Redacted(BitArray))
}

/// A key ring from the current key and retired keys still accepted for
/// opening.
pub fn keys(current: Redacted(BitArray), previous: List(Redacted(BitArray))) {
  Keys(key(current), list.map(previous, key))
}

/// A key ring with one random key, for the in-memory stores.
pub fn ephemeral() -> Keys {
  keys(redacted.new(crypto.strong_random_bytes(32)), [])
}

fn key(secret: Redacted(BitArray)) -> Key {
  let digest =
    crypto.hash(crypto.Sha256, <<
      "warden sealing key":utf8,
      redacted.reveal(secret):bits,
    >>)
  let assert Ok(id) = bit_array.slice(digest, 0, 8)
  Key(id:, secret:)
}

fn aad(kind: String, record_key: String, version: Int) -> BitArray {
  <<kind:utf8, 0, record_key:utf8, 0, version:64>>
}

pub fn seal(
  keys: Keys,
  kind kind: String,
  key record_key: String,
  version version: Int,
  plaintext plaintext: BitArray,
) -> BitArray {
  let Key(id:, secret:) = keys.current
  let assert Ok(cipher) = block.aes_256(redacted.reveal(secret))
  let context = aead.gcm(cipher)
  let nonce = crypto.strong_random_bytes(12)
  let assert Ok(#(ciphertext, tag)) =
    aead.seal_with_aad(
      context,
      nonce:,
      plaintext:,
      additional_data: aad(kind, record_key, version),
    )
  <<1, id:bits, nonce:bits, tag:bits, ciphertext:bits>>
}

pub fn open(
  keys: Keys,
  kind kind: String,
  key record_key: String,
  version version: Int,
  sealed sealed: BitArray,
) -> Result(BitArray, Nil) {
  case sealed {
    <<
      1,
      id:bytes-size(8),
      nonce:bytes-size(12),
      tag:bytes-size(16),
      ciphertext:bytes,
    >> -> {
      use Key(secret:, ..) <- result.try(
        list.find([keys.current, ..keys.previous], fn(k) { k.id == id }),
      )
      use cipher <- result.try(block.aes_256(redacted.reveal(secret)))
      aead.open_with_aad(
        aead.gcm(cipher),
        nonce:,
        tag:,
        ciphertext:,
        additional_data: aad(kind, record_key, version),
      )
    }
    _ -> Error(Nil)
  }
}
