//// Provider metadata and signing keys for the native backend.
////
//// `discover` loads discovery and the JWKS once at startup through Warden's
//// transport. A supervised actor then holds them, reloads both on a timer
//// derived from `cache-control` (bounded), and refreshes keys on demand for
//// an unknown `kid`, at most once per second. A failed reload keeps the
//// previous values. Unusable JWKs are skipped (RFC 7517 §5).

import gleam/bit_array
import gleam/dict
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/erlang/atom
import gleam/erlang/process.{type Subject}
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/otp/actor
import gleam/result
import gleam/string
import gose/jose/jwk
import gose/jose/key_set.{type JwkSet}
import warden/internal/call
import warden/internal/protocol.{type Failure, type Metadata}
import warden/internal/transport

pub type Discovered {
  Discovered(metadata: Metadata, jwks_uri: String, keys: JwkSet, ttl_ms: Int)
}

pub type Snapshot {
  Snapshot(metadata: Metadata, keys: JwkSet)
}

// ---------------------------------------------------------------------------
// HTTP helpers shared by the native backend

/// Map a transport failure to the shared classification.
pub fn transport_failure(failure: transport.Failure) -> Failure {
  protocol.Transport(
    sent: failure.stage == transport.Sent,
    class: transport.class_name(failure.class),
  )
}

/// The OAuth error code of a non-success response body (RFC 6749 §5.2), or
/// `none`. Only the code is kept; descriptions are discarded.
pub fn error_code(body: BitArray) -> String {
  bit_array.to_string(body)
  |> result.try(fn(text) {
    json.parse(text, decode.at(["error"], decode.string))
    |> result.replace_error(Nil)
  })
  |> result.map(known_error)
  |> result.unwrap("none")
}

fn known_error(code: String) -> String {
  case code {
    "invalid_request"
    | "invalid_client"
    | "invalid_grant"
    | "unauthorized_client"
    | "unsupported_grant_type"
    | "invalid_scope"
    | "invalid_token"
    | "insufficient_scope" -> code
    _ -> "other"
  }
}

/// A JSON object from a success response, or the closed failure.
pub fn json_response(
  result: Result(transport.Response, transport.Failure),
) -> Result(#(Dynamic, transport.Response), Failure) {
  case result {
    Error(failure) -> Error(transport_failure(failure))
    Ok(response) if response.status == 200 || response.status == 201 ->
      case bit_array.to_string(response.body) {
        Ok(text) ->
          case json.parse(text, decode.dynamic) {
            Ok(value) ->
              case
                decode.run(value, decode.dict(decode.string, decode.dynamic))
              {
                Ok(_) -> Ok(#(value, response))
                Error(_) -> Error(protocol.Malformed)
              }
            Error(_) -> Error(protocol.Malformed)
          }
        Error(Nil) -> Error(protocol.Malformed)
      }
    Ok(response) ->
      Error(protocol.Endpoint(
        status: response.status,
        error: error_code(response.body),
      ))
  }
}

pub fn get(
  policy: transport.Policy,
  url: String,
) -> Result(transport.Response, transport.Failure) {
  transport.send(
    policy,
    transport.Request(
      transport.Get,
      url,
      [#("accept", "application/json")],
      None,
    ),
  )
}

// ---------------------------------------------------------------------------
// Discovery

pub fn discovery_url(issuer: String) -> String {
  let base = case string.ends_with(issuer, "/") {
    True -> string.drop_end(issuer, 1)
    False -> issuer
  }
  base <> "/.well-known/openid-configuration"
}

pub fn discover(
  issuer: String,
  policy: transport.Policy,
) -> Result(Discovered, Failure) {
  use #(document, response) <- result.try(
    get(policy, discovery_url(issuer)) |> json_response,
  )
  use #(metadata, jwks_uri) <- result.try(
    decode.run(document, metadata_decoder())
    |> result.replace_error(protocol.Malformed),
  )
  use _ <- result.try(case metadata.issuer == issuer {
    True -> Ok(Nil)
    False -> Error(protocol.Policy("issuer_mismatch"))
  })
  use keys <- result.try(load_keys(jwks_uri, policy))
  Ok(Discovered(metadata:, jwks_uri:, keys:, ttl_ms: ttl(response.headers)))
}

pub fn load_keys(
  uri: String,
  policy: transport.Policy,
) -> Result(JwkSet, Failure) {
  case get(policy, uri) {
    Error(failure) -> Error(transport_failure(failure))
    Ok(response) if response.status == 200 ->
      bit_array.to_string(response.body)
      |> result.try(parse_key_set)
      |> result.replace_error(protocol.Malformed)
    Ok(response) ->
      Error(protocol.Endpoint(status: response.status, error: "none"))
  }
}

/// Parse a JWK set, ignoring unusable keys (RFC 7517 §5). X.509 members
/// (`x5c`, `x5t`, `x5t#S256`, `x5u`) are removed before parsing: Warden
/// verifies with the key members themselves and does not validate
/// certificate chains, and gose 2.2.0 refuses JWKs that carry them.
pub fn parse_key_set(text: String) -> Result(JwkSet, Nil) {
  let entry = decode.dict(decode.string, decode.dynamic)
  use keys <- result.map(
    json.parse(text, decode.at(["keys"], decode.list(entry)))
    |> result.replace_error(Nil),
  )
  keys
  |> list.filter_map(fn(fields) {
    fields
    |> dict.drop(["x5c", "x5t", "x5t#S256", "x5u"])
    |> to_dynamic
    |> jwk.from_dynamic
    |> result.replace_error(Nil)
  })
  |> key_set.from_list
}

@external(erlang, "gleam_stdlib", "identity")
fn to_dynamic(value: a) -> Dynamic

/// Reload interval from `cache-control: max-age`, bounded to [60 s, 1 day];
/// one hour when absent.
fn ttl(headers: List(#(String, String))) -> Int {
  let max_age =
    list.key_find(headers, "cache-control")
    |> result.try(fn(value) {
      value
      |> string.lowercase
      |> string.split(",")
      |> list.find_map(fn(part) {
        case string.split_once(string.trim(part), "=") {
          Ok(#("max-age", seconds)) -> int.parse(string.trim(seconds))
          _ -> Error(Nil)
        }
      })
    })
  case max_age {
    Ok(seconds) -> int.clamp(seconds, 60, 86_400) * 1000
    Error(Nil) -> 3_600_000
  }
}

fn metadata_decoder() -> decode.Decoder(#(Metadata, String)) {
  let strings = decode.list(decode.string)
  let optional_string = fn(name, next) {
    decode.optional_field(name, None, decode.optional(decode.string), next)
  }
  use issuer <- decode.field("issuer", decode.string)
  use authorization_endpoint <- decode.field(
    "authorization_endpoint",
    decode.string,
  )
  use jwks_uri <- decode.field("jwks_uri", decode.string)
  use token_endpoint <- optional_string("token_endpoint")
  use userinfo_endpoint <- optional_string("userinfo_endpoint")
  use introspection_endpoint <- optional_string("introspection_endpoint")
  use end_session_endpoint <- optional_string("end_session_endpoint")
  use code_challenge_methods <- decode.optional_field(
    "code_challenge_methods_supported",
    [],
    strings,
  )
  use grant_types <- decode.optional_field(
    "grant_types_supported",
    ["authorization_code", "implicit"],
    strings,
  )
  use response_modes <- decode.optional_field(
    "response_modes_supported",
    ["query", "fragment"],
    strings,
  )
  use auth_methods <- decode.optional_field(
    "token_endpoint_auth_methods_supported",
    ["client_secret_basic"],
    strings,
  )
  use auth_signing_algorithms <- decode.optional_field(
    "token_endpoint_auth_signing_alg_values_supported",
    [],
    strings,
  )
  use id_token_algorithms <- decode.field(
    "id_token_signing_alg_values_supported",
    strings,
  )
  use issuer_parameter_supported <- decode.optional_field(
    "authorization_response_iss_parameter_supported",
    False,
    decode.bool,
  )
  use requires_par <- decode.optional_field(
    "require_pushed_authorization_requests",
    False,
    decode.bool,
  )
  use requires_signed_request_object <- decode.optional_field(
    "require_signed_request_object",
    False,
    decode.bool,
  )
  decode.success(#(
    protocol.Metadata(
      issuer:,
      authorization_endpoint:,
      token_endpoint:,
      userinfo_endpoint:,
      introspection_endpoint:,
      end_session_endpoint:,
      code_challenge_methods:,
      grant_types:,
      response_modes:,
      auth_methods:,
      auth_signing_algorithms:,
      id_token_algorithms:,
      issuer_parameter_supported:,
      requires_par:,
      requires_signed_request_object:,
    ),
    jwks_uri,
  ))
}

// ---------------------------------------------------------------------------
// Cache actor

pub opaque type Message {
  Get(reply: Subject(Snapshot))
  RefreshKeys(kid: Option(String), reply: Subject(Snapshot))
  Reload
}

type State {
  State(
    self: Subject(Message),
    issuer: String,
    policy: transport.Policy,
    discovered: Discovered,
    last_key_refresh: Int,
    attempted_kids: List(String),
  )
}

pub type Provider {
  Provider(subject: Subject(Message), timeout: Int)
}

const key_refresh_interval_ms = 1000

pub fn start(
  name: process.Name(Message),
  issuer: String,
  policy: transport.Policy,
  seed: Option(Discovered),
) -> actor.StartResult(Subject(Message)) {
  actor.new_with_initialiser(policy.timeout_ms * 3, fn(self) {
    // A restarted actor rediscovers; the first start uses the startup load.
    let loaded = case seed {
      Some(discovered) -> Ok(discovered)
      None -> discover(issuer, policy)
    }
    case loaded {
      Error(_) -> Error("provider discovery failed")
      Ok(discovered) -> {
        process.send_after(self, discovered.ttl_ms, Reload)
        actor.initialised(
          State(
            self:,
            issuer:,
            policy:,
            discovered:,
            last_key_refresh: monotonic_ms(),
            attempted_kids: [],
          ),
        )
        |> actor.returning(self)
        |> Ok
      }
    }
  })
  |> actor.named(name)
  |> actor.on_message(handle)
  |> actor.start
}

fn snapshot(state: State) -> Snapshot {
  Snapshot(state.discovered.metadata, state.discovered.keys)
}

fn handle(state: State, message: Message) -> actor.Next(State, Message) {
  case message {
    Get(reply) -> {
      process.send(reply, snapshot(state))
      actor.continue(state)
    }
    RefreshKeys(kid, reply) -> {
      let now = monotonic_ms()
      // At most one refresh per second, except that each new kid may
      // trigger one immediate refresh (bounded list of recent kids).
      let new_kid = case kid {
        Some(k) -> !list.contains(state.attempted_kids, k)
        None -> False
      }
      let attempted_kids = case kid {
        Some(k) if new_kid -> list.take([k, ..state.attempted_kids], 64)
        _ -> state.attempted_kids
      }
      let state = case
        new_kid || now - state.last_key_refresh >= key_refresh_interval_ms
      {
        False -> state
        True ->
          case load_keys(state.discovered.jwks_uri, state.policy) {
            Ok(keys) ->
              State(
                ..state,
                discovered: Discovered(..state.discovered, keys:),
                last_key_refresh: now,
                attempted_kids:,
              )
            Error(_) -> State(..state, last_key_refresh: now, attempted_kids:)
          }
      }
      process.send(reply, snapshot(state))
      actor.continue(state)
    }
    Reload -> {
      let state = case discover(state.issuer, state.policy) {
        Ok(discovered) -> State(..state, discovered:)
        Error(_) -> state
      }
      process.send_after(state.self, state.discovered.ttl_ms, Reload)
      actor.continue(state)
    }
  }
}

pub fn snapshot_of(provider: Provider) -> Result(Snapshot, Failure) {
  call.call(provider.subject, provider.timeout, Get)
  |> result.replace_error(protocol.NotReady)
}

pub fn refresh_keys(
  provider: Provider,
  kid: Option(String),
) -> Result(Snapshot, Failure) {
  call.call(provider.subject, provider.timeout, RefreshKeys(kid, _))
  |> result.replace_error(protocol.NotReady)
}

@external(erlang, "erlang", "monotonic_time")
fn monotonic_time(unit: atom.Atom) -> Int

fn monotonic_ms() -> Int {
  monotonic_time(atom.create("millisecond"))
}
