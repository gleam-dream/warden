//// Test-only `oidcc_http_adapter` over Warden's transport, so the raw-oidcc
//// differential and probes (oidcc is a dev-dependency) send through the same
//// bounded, verified HTTPS client as Warden.
////
//// oidcc calls `request/5` with `httpc`-shaped arguments and expects an
//// `httpc`-shaped result. Before oidcc sees a response:
//// - a non-success body is reduced to `{"error": Code}` (RFC 6749 charset,
////   at most 64 bytes) or emptied, because oidcc places error bodies in error
////   terms and telemetry metadata (decision D3);
//// - a success body declared as JSON must parse, or the request fails as
////   `{sent, malformed_response}`.
//// Failures have the closed shape `{error, {warden_transport, Stage, Class}}`.

import gleam/bit_array
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/erlang/atom.{type Atom}
import gleam/erlang/charlist
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import warden/internal/transport

/// The adapter term for oidcc's `request_opts.http_adapter`.
pub fn adapter(policy: transport.Policy) -> Dynamic {
  to_dynamic(#(atom.create("oidcc_transport"), policy))
}

/// `oidcc_http_adapter:request/5`.
pub fn request(
  method: Dynamic,
  request: Dynamic,
  http_options: Dynamic,
  _request_options: Dynamic,
  policy: transport.Policy,
) -> Dynamic {
  case decode_request(method, request) {
    Error(Nil) -> failure(transport.NotSent, transport.InvalidRequest)
    Ok(request) -> {
      let timeout =
        decode.run(http_options, decode.list(timeout_option()))
        |> result.unwrap([])
        |> list.filter_map(fn(x) { x })
        |> list.first
        |> result.unwrap(policy.timeout_ms)
      let policy =
        transport.Policy(
          ..policy,
          timeout_ms: int.min(timeout, policy.timeout_ms),
        )
      case transport.send(policy, request) {
        Error(transport.Failure(stage:, class:)) -> failure(stage, class)
        Ok(response) ->
          case sanitise(response) {
            Error(Nil) -> failure(transport.Sent, transport.MalformedResponse)
            Ok(body) ->
              to_dynamic(#(
                a("ok"),
                #(
                  #(
                    charlist.from_string("HTTP/1.1"),
                    response.status,
                    charlist.from_string("OK"),
                  ),
                  list.map(response.headers, fn(h) {
                    #(charlist.from_string(h.0), h.1)
                  }),
                  body,
                ),
              ))
          }
      }
    }
  }
}

fn timeout_option() -> decode.Decoder(Result(Int, Nil)) {
  decode.one_of(
    {
      use key <- decode.field(0, atom.decoder())
      use value <- decode.field(1, decode.int)
      decode.success(case atom.to_string(key) {
        "timeout" -> Ok(value)
        _ -> Error(Nil)
      })
    },
    [decode.success(Error(Nil))],
  )
}

fn decode_request(
  method: Dynamic,
  request: Dynamic,
) -> Result(transport.Request, Nil) {
  use method <- result.try(
    decode.run(method, atom.decoder())
    |> result.replace_error(Nil)
    |> result.try(fn(m) {
      case atom.to_string(m) {
        "get" -> Ok(transport.Get)
        "post" -> Ok(transport.Post)
        _ -> Error(Nil)
      }
    }),
  )
  let header = {
    use name <- decode.field(0, decode.dynamic)
    use value <- decode.field(1, decode.dynamic)
    decode.success(#(name, value))
  }
  let shape = {
    use url <- decode.field(0, decode.dynamic)
    use headers <- decode.field(1, decode.list(header))
    use body <- decode.optional_field(3, None, decode.map(decode.dynamic, Some))
    use content_type <- decode.optional_field(
      2,
      None,
      decode.map(decode.dynamic, Some),
    )
    decode.success(#(url, headers, content_type, body))
  }
  use #(url, headers, content_type, body) <- result.try(
    decode.run(request, shape) |> result.replace_error(Nil),
  )
  use url <- result.try(text(url))
  use headers <- result.try(
    list.try_map(headers, fn(h) {
      use name <- result.try(text(h.0))
      use value <- result.try(text(h.1))
      Ok(#(name, value))
    }),
  )
  use headers <- result.try(case content_type {
    Some(ct) ->
      text(ct) |> result.map(fn(ct) { [#("content-type", ct), ..headers] })
    None -> Ok(headers)
  })
  use body <- result.try(case body {
    Some(body) -> bytes(body) |> result.map(Some)
    None -> Ok(None)
  })
  Ok(transport.Request(method:, url:, headers:, body:))
}

/// iodata or chardata as a UTF-8 string.
fn text(value: Dynamic) -> Result(String, Nil) {
  use bits <- result.try(bytes(value))
  bit_array.to_string(bits)
}

fn bytes(value: Dynamic) -> Result(BitArray, Nil) {
  case decode.run(value, decode.bit_array) {
    Ok(bits) -> Ok(bits)
    Error(_) ->
      case characters_to_binary(value) |> decode.run(decode.bit_array) {
        Ok(bits) -> Ok(bits)
        Error(_) -> Error(Nil)
      }
  }
}

fn sanitise(response: transport.Response) -> Result(BitArray, Nil) {
  case response.status {
    200 | 201 ->
      case json_declared(response.headers) {
        False -> Ok(response.body)
        True ->
          case bit_array.to_string(response.body) {
            Ok(text) ->
              json.parse(text, decode.dynamic)
              |> result.replace(response.body)
              |> result.replace_error(Nil)
            Error(Nil) -> Error(Nil)
          }
      }
    _ -> Ok(error_code_body(response.body))
  }
}

fn error_code_body(body: BitArray) -> BitArray {
  let code =
    bit_array.to_string(body)
    |> result.try(fn(text) {
      json.parse(text, decode.at(["error"], decode.string))
      |> result.replace_error(Nil)
    })
  case code {
    Ok(code) ->
      case string.length(code) <= 64 && code != "" && oauth_charset(code) {
        True ->
          json.object([#("error", json.string(code))])
          |> json.to_string
          |> bit_array.from_string
        False -> <<>>
      }
    Error(Nil) -> <<>>
  }
}

fn oauth_charset(code: String) -> Bool {
  code
  |> bit_array.from_string
  |> all_bytes(fn(b) {
    b == 0x20
    || b == 0x21
    || { b >= 0x23 && b <= 0x5B }
    || { b >= 0x5D && b <= 0x7E }
  })
}

fn all_bytes(bits: BitArray, check: fn(Int) -> Bool) -> Bool {
  case bits {
    <<>> -> True
    <<b, rest:bytes>> -> check(b) && all_bytes(rest, check)
    _ -> False
  }
}

fn json_declared(headers: List(#(String, String))) -> Bool {
  case list.key_find(headers, "content-type") {
    Ok(value) -> {
      let media =
        value
        |> string.split(";")
        |> list.first
        |> result.unwrap("")
        |> string.trim
        |> string.lowercase
      media == "application/json" || string.ends_with(media, "+json")
    }
    Error(Nil) -> False
  }
}

fn failure(stage: transport.Stage, class: transport.Class) -> Dynamic {
  let stage = case stage {
    transport.NotSent -> a("not_sent")
    transport.Sent -> a("sent")
  }
  to_dynamic(#(
    a("error"),
    #(a("warden_transport"), stage, a(transport.class_name(class))),
  ))
}

fn a(name: String) -> Atom {
  atom.create(name)
}

@external(erlang, "gleam_stdlib", "identity")
fn to_dynamic(value: a) -> Dynamic

@external(erlang, "unicode", "characters_to_binary")
fn characters_to_binary(value: Dynamic) -> Dynamic
