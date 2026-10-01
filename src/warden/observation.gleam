//// Typed observation events, as `sinal` descriptors over `:telemetry`.
////
//// Every event carries closed, non-secret values only: no token, code,
//// state, nonce, verifier, secret, claim, query string, header or body ever
//// reaches an event. Subscribe with `sinal.observe` or `sinal.attach`:
////
//// ```gleam
//// let assert Ok(id) = sinal.handler_id("my-app-warden-http")
//// sinal.observe(id, observation.http_request(), fn(measurements, request) {
////   // measurements.duration_ms, request.host, request.outcome, ...
////   Nil
//// })
//// ```

import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/erlang/atom
import sinal
import sinal/fields

/// `[warden, http, request]`: one outbound HTTPS request made by Warden
/// (discovery, keys, token, userinfo, introspection, revocation), emitted
/// once it completes or fails.
pub type HttpMeasurements {
  HttpMeasurements(duration_ms: Int)
}

pub type HttpRequest {
  HttpRequest(method: HttpMethod, host: String, path: String, outcome: Outcome)
}

pub type HttpMethod {
  Get
  Post
}

/// A response status, or a failure with send evidence and closed class.
/// `sent: False` proves the request was not transmitted.
pub type Outcome {
  Status(code: Int)
  Failed(sent: Bool, class: String)
}

/// The descriptor for `[warden, http, request]`. On the wire the metadata is
/// `#{method => get | post, host => Binary, path => Binary,
/// outcome => {status, Code} | {failure, not_sent | sent, Class}}` and the
/// measurements are `#{duration_ms => Integer}`.
pub fn http_request() -> sinal.Event(HttpMeasurements, HttpRequest) {
  let measurements =
    fields.int(atom.create("duration_ms"))
    |> fields.imap(HttpMeasurements, fn(m) { m.duration_ms })
  // Keys are distinct literals and the name is non-empty: neither assert can
  // fail.
  let assert Ok(target) =
    fields.pair(
      fields.string(atom.create("host")),
      fields.string(atom.create("path")),
    )
  let assert Ok(head) = fields.pair(method_field(), target)
  let assert Ok(metadata) = fields.pair(head, outcome_field())
  let metadata =
    fields.imap(
      metadata,
      fn(m) {
        let #(#(method, #(host, path)), outcome) = m
        HttpRequest(method:, host:, path:, outcome:)
      },
      fn(r) { #(#(r.method, #(r.host, r.path)), r.outcome) },
    )
  let assert Ok(event) =
    sinal.event(
      [atom.create("warden"), atom.create("http"), atom.create("request")],
      measurements,
      metadata,
    )
  event
}

fn method_field() -> fields.Fields(HttpMethod) {
  fields.field(
    atom.create("method"),
    fn(method) {
      Ok(
        atom.to_dynamic(
          atom.create(case method {
            Get -> "get"
            Post -> "post"
          }),
        ),
      )
    },
    fn(raw) {
      case decode.run(raw, atom.decoder()) {
        Ok(name) ->
          case atom.to_string(name) {
            "get" -> Ok(Get)
            "post" -> Ok(Post)
            _ -> Error(fields.FieldDecodeError("Expected get or post"))
          }
        Error(_) -> Error(fields.FieldDecodeError("Expected an atom"))
      }
    },
  )
}

fn outcome_field() -> fields.Fields(Outcome) {
  fields.field(
    atom.create("outcome"),
    fn(outcome) { Ok(encode_outcome(outcome)) },
    fn(raw) {
      let status = {
        use tag <- decode.field(0, atom.decoder())
        use code <- decode.field(1, decode.int)
        case atom.to_string(tag) {
          "status" -> decode.success(Status(code))
          _ -> decode.failure(Status(0), "outcome")
        }
      }
      let failure = {
        use tag <- decode.field(0, atom.decoder())
        use stage <- decode.field(1, atom.decoder())
        use class <- decode.field(2, atom.decoder())
        case atom.to_string(tag), atom.to_string(stage) {
          "failure", "sent" ->
            decode.success(Failed(True, atom.to_string(class)))
          "failure", "not_sent" ->
            decode.success(Failed(False, atom.to_string(class)))
          _, _ -> decode.failure(Status(0), "outcome")
        }
      }
      case decode.run(raw, decode.one_of(status, [failure])) {
        Ok(outcome) -> Ok(outcome)
        Error(_) -> Error(fields.FieldDecodeError("Expected an outcome tuple"))
      }
    },
  )
}

fn encode_outcome(outcome: Outcome) -> Dynamic {
  case outcome {
    Status(code) -> to_dynamic(#(atom.create("status"), code))
    Failed(sent:, class:) ->
      to_dynamic(#(
        atom.create("failure"),
        atom.create(case sent {
          True -> "sent"
          False -> "not_sent"
        }),
        atom.create(class),
      ))
  }
}

@external(erlang, "gleam_stdlib", "identity")
fn to_dynamic(value: a) -> Dynamic
