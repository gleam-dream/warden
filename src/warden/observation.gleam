//// Typed observation events, as `sinal` descriptors over `:telemetry`.
////
//// Every event carries closed, non-secret values only: no token, code,
//// state, nonce, verifier, secret, claim, query string, header or body ever
//// reaches an event. Subscribe with `sinal.observe` or `sinal.attach`:
////
//// ```gleam
//// sinal.observe(observation.http_request(), fn(measurements, request) {
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
    fields.record({
      use duration_ms <- fields.parameter
      HttpMeasurements(duration_ms:)
    })
    |> fields.and(fields.int("duration_ms"), fn(m: HttpMeasurements) {
      m.duration_ms
    })
    |> fields.build
  let metadata =
    fields.record({
      use method <- fields.parameter
      use host <- fields.parameter
      use path <- fields.parameter
      use outcome <- fields.parameter
      HttpRequest(method:, host:, path:, outcome:)
    })
    |> fields.and(method_field(), fn(r: HttpRequest) { r.method })
    |> fields.and(fields.string("host"), fn(r) { r.host })
    |> fields.and(fields.string("path"), fn(r) { r.path })
    |> fields.and(outcome_field(), fn(r) { r.outcome })
    |> fields.build
  sinal.event(["warden", "http", "request"], measurements, metadata)
}

fn method_field() -> fields.Fields(HttpMethod) {
  fields.field(
    "method",
    fn(method) {
      atom.to_dynamic(
        atom.create(case method {
          Get -> "get"
          Post -> "post"
        }),
      )
    },
    atom.decoder()
      |> decode.then(fn(name) {
        case atom.to_string(name) {
          "get" -> decode.success(Get)
          "post" -> decode.success(Post)
          _ -> decode.failure(Get, "get or post")
        }
      }),
  )
}

fn outcome_field() -> fields.Fields(Outcome) {
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
      "failure", "sent" -> decode.success(Failed(True, atom.to_string(class)))
      "failure", "not_sent" ->
        decode.success(Failed(False, atom.to_string(class)))
      _, _ -> decode.failure(Status(0), "outcome")
    }
  }
  fields.field("outcome", encode_outcome, decode.one_of(status, [failure]))
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
