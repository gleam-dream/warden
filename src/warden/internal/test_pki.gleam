//// Disposable test PKI for `warden/testing`: a P-256 root and a leaf for
//// `localhost` and `127.0.0.1` it signed, from OTP's own
//// `public_key:pkix_test_data/1`. OTP refuses a self-signed peer even when
//// it is the configured anchor, so the leaf must be CA-issued. Nothing is
//// written to disk.

import gleam/dict
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/erlang/atom
import gleam/erlang/charlist
import gleam/list
import gleam/result

pub type Pki {
  Pki(
    /// PEM text of the root: the trust anchor.
    ca_pem: String,
    ca_der: BitArray,
    /// The leaf certificate (DER) and its key term for `ssl:listen`.
    certificate: BitArray,
    key: Dynamic,
  )
}

pub fn generate() -> Result(Pki, Nil) {
  let a = atom.create
  let key = to_dynamic(#(a("key"), #(a("namedCurve"), a("secp256r1"))))
  let digest = to_dynamic(#(a("digest"), a("sha256")))
  let san = #(
    a("Extension"),
    // id-ce-subjectAltName
    #(2, 5, 29, 17),
    False,
    [
      to_dynamic(#(a("dNSName"), charlist.from_string("localhost"))),
      to_dynamic(#(a("iPAddress"), <<127, 0, 0, 1>>)),
    ],
  )
  let conf =
    dict.from_list([
      #(a("root"), to_dynamic([key, digest])),
      #(
        a("peer"),
        to_dynamic([key, digest, to_dynamic(#(a("extensions"), [san]))]),
      ),
    ])
  use options <- result.try(
    decode.run(pkix_test_data(conf), decode.list(decode.dynamic))
    |> result.replace_error(Nil),
  )
  let find = fn(name: String) {
    list.find_map(options, fn(option) {
      let tagged = {
        use tag <- decode.field(0, atom.decoder())
        use value <- decode.field(1, decode.dynamic)
        case atom.to_string(tag) == name {
          True -> decode.success(value)
          False -> decode.failure(value, name)
        }
      }
      decode.run(option, tagged) |> result.replace_error(Nil)
    })
  }
  use certificate <- result.try(
    find("cert")
    |> result.try(fn(v) {
      decode.run(v, decode.bit_array) |> result.replace_error(Nil)
    }),
  )
  use key <- result.try(find("key"))
  use ca_der <- result.try(
    find("cacerts")
    |> result.try(fn(v) {
      decode.run(v, decode.list(decode.bit_array)) |> result.replace_error(Nil)
    })
    |> result.try(list.first),
  )
  let pem = pem_encode([#(a("Certificate"), ca_der, a("not_encrypted"))])
  Ok(Pki(ca_pem: pem, ca_der:, certificate:, key:))
}

@external(erlang, "public_key", "pkix_test_data")
fn pkix_test_data(conf: dict.Dict(atom.Atom, Dynamic)) -> Dynamic

@external(erlang, "public_key", "pem_encode")
fn pem_encode(entries: List(#(atom.Atom, BitArray, atom.Atom))) -> String

@external(erlang, "gleam_stdlib", "identity")
fn to_dynamic(value: a) -> Dynamic
