//// Provider metadata and signing keys for the native backend.
////
//// Each cache incarnation discovers metadata and the JWKS through Warden's
//// transport. The actor then holds them and reloads both on a timer
//// derived from `cache-control` (bounded), and refreshes keys on demand for
//// an unknown `kid`, at most once per second. A failed reload keeps the
//// previous values. Unusable JWKs are skipped (RFC 7517 §5).
////
//// Each asynchronous fetch belongs to one cache incarnation. Its guardian
//// terminates the worker on owner loss, including while a telemetry observer
//// blocks after HTTP completes. Results and timers address the process, not
//// its restart-stable name. Worker loss retains the last accepted snapshot;
//// discovery retry and reload keep their existing bounded cadence.

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
import warden/internal/key_policy
import warden/internal/native/provider_fetch.{type Background}
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

/// Discovery and the first key load, both within `deadline` (monotonic
/// milliseconds): each request gets at most the time remaining.
pub fn discover(
  issuer: String,
  policy: transport.Policy,
  deadline: Int,
) -> Result(Discovered, Failure) {
  use policy <- result.try(within_deadline(policy, deadline))
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
  use policy <- result.try(within_deadline(policy, deadline))
  use keys <- result.try(load_keys(jwks_uri, policy))
  Ok(Discovered(metadata:, jwks_uri:, keys:, ttl_ms: ttl(response.headers)))
}

/// Rediscovery outside `warden.start` (background discovery, reload): two
/// request timeouts.
fn background_deadline(policy: transport.Policy) -> Int {
  transport.monotonic_ms() + 2 * policy.timeout_ms
}

fn within_deadline(
  policy: transport.Policy,
  deadline: Int,
) -> Result(transport.Policy, Failure) {
  case deadline - transport.monotonic_ms() {
    remaining if remaining <= 0 ->
      Error(protocol.Transport(sent: False, class: "timeout"))
    remaining ->
      Ok(
        transport.Policy(
          ..policy,
          timeout_ms: int.min(policy.timeout_ms, remaining),
        ),
      )
  }
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
  |> list.filter(key_policy.strong_enough)
  |> list.filter(key_policy.supported_curve)
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
  use revocation_endpoint <- optional_string("revocation_endpoint")
  use end_session_endpoint <- optional_string("end_session_endpoint")
  use code_challenge_methods <- decode.optional_field(
    "code_challenge_methods_supported",
    None,
    decode.map(strings, Some),
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
      revocation_endpoint:,
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
  Get(reply: Subject(Option(Snapshot)))
  FirstDiscovery(reply: Subject(Result(Metadata, Failure)))
  RefreshKeys(kid: Option(String), reply: Subject(Option(Snapshot)))
  Discover
  Reload
  KeysLoaded(process.Pid, Result(JwkSet, Failure))
  Reloaded(process.Pid, Result(Discovered, Failure))
  Discovery(process.Pid, Result(Discovered, Failure))
  FetchExited(process.Down)
}

/// Network fetches run in a separate process, one at a time, so the actor
/// keeps answering from its last good snapshot while a provider is slow.
type Fetch {
  Idle
  /// Callers waiting for the key refresh in flight.
  FetchingKeys(worker: Background, waiters: List(Subject(Option(Snapshot))))
  Reloading(worker: Background)
  Discovering(worker: Background)
}

type InitialDiscovery {
  Pending(waiter: Option(Subject(Result(Metadata, Failure))))
  Completed(Result(Metadata, Failure))
}

type State {
  State(
    self: Subject(Message),
    issuer: String,
    policy: transport.Policy,
    accept: fn(Metadata) -> Bool,
    discovered: Option(Discovered),
    initial: InitialDiscovery,
    /// Delay before the next background discovery attempt.
    backoff_ms: Int,
    last_key_refresh: Int,
    attempted_kids: List(String),
    fetch: Fetch,
  )
}

pub type Provider {
  Provider(subject: Subject(Message), timeout: Int)
}

const key_refresh_interval_ms = 1000

const first_backoff_ms = 1000

const max_backoff_ms = 60_000

/// Start an empty provider cache. Each incarnation discovers independently
/// in the background and answers `NotReady` until compatible discovery succeeds.
/// One initial outcome (metadata or failure, never keys) is retained so manual
/// startup can await the first attempt without racing its completion.
pub fn start(
  name: process.Name(Message),
  issuer: String,
  policy: transport.Policy,
  accept: fn(Metadata) -> Bool,
) -> actor.StartResult(Subject(Message)) {
  actor.new_with_initialiser(1000, fn(named) {
    // Timers and fetch results belong to this incarnation, never its name.
    let self = process.new_subject()
    process.send(self, Discover)
    actor.initialised(State(
      self:,
      issuer:,
      policy:,
      accept:,
      discovered: None,
      initial: Pending(None),
      backoff_ms: first_backoff_ms,
      last_key_refresh: monotonic_ms(),
      attempted_kids: [],
      fetch: Idle,
    ))
    |> actor.selecting(
      process.new_selector()
      |> process.select(named)
      |> process.select(self)
      |> process.select_monitors(FetchExited),
    )
    |> actor.returning(named)
    |> Ok
  })
  |> actor.named(name)
  |> actor.on_message(handle)
  |> actor.start
}

fn snapshot(state: State) -> Option(Snapshot) {
  option.map(state.discovered, fn(d) { Snapshot(d.metadata, d.keys) })
}

/// Completion and guardian DOWN are ordered signals from the same process.
/// Matching the active guardian also makes a delayed terminal message inert.
fn active_background(fetch: Fetch) -> Option(Background) {
  case fetch {
    Idle -> None
    FetchingKeys(worker, _) | Reloading(worker) | Discovering(worker) ->
      Some(worker)
  }
}

fn finish_background(state: State, pid: process.Pid) -> Bool {
  case active_background(state.fetch) {
    Some(worker) if worker.pid == pid -> {
      process.demonitor_process(worker.monitor)
      True
    }
    _ -> False
  }
}

fn fetch_exited(
  state: State,
  down: process.Down,
) -> actor.Next(State, Message) {
  case down, active_background(state.fetch) {
    process.ProcessDown(monitor, pid, _), Some(worker)
      if monitor == worker.monitor && pid == worker.pid
    ->
      case state.fetch {
        FetchingKeys(_, _) ->
          handle(state, KeysLoaded(pid, Error(protocol.Unmapped)))
        Reloading(_) -> handle(state, Reloaded(pid, Error(protocol.Unmapped)))
        Discovering(_) ->
          handle(state, Discovery(pid, Error(protocol.Unmapped)))
        Idle -> actor.continue(state)
      }
    _, _ -> actor.continue(state)
  }
}

fn handle(state: State, message: Message) -> actor.Next(State, Message) {
  case message {
    FetchExited(down) -> fetch_exited(state, down)
    FirstDiscovery(reply) ->
      case state.initial {
        Completed(outcome) -> {
          process.send(reply, outcome)
          actor.continue(state)
        }
        Pending(None) ->
          actor.continue(State(..state, initial: Pending(Some(reply))))
        Pending(Some(_)) -> {
          // Only manual startup owns this single bounded observer.
          process.send(reply, Error(protocol.Unmapped))
          actor.continue(state)
        }
      }
    Get(reply) -> {
      process.send(reply, snapshot(state))
      actor.continue(state)
    }
    Discover ->
      case state.fetch {
        Idle -> {
          let issuer = state.issuer
          let policy = state.policy
          let worker =
            provider_fetch.start(
              state.self,
              fn() { discover(issuer, policy, background_deadline(policy)) },
              Discovery,
            )
          actor.continue(State(..state, fetch: Discovering(worker)))
        }
        _ -> actor.continue(state)
      }
    Discovery(pid, result) ->
      case finish_background(state, pid) {
        False -> actor.continue(state)
        True -> {
          let state =
            complete_initial(state, result.map(result, fn(d) { d.metadata }))
          case result {
            Ok(discovered) ->
              case state.accept(discovered.metadata) {
                True -> {
                  process.send_after(state.self, discovered.ttl_ms, Reload)
                  actor.continue(
                    State(
                      ..state,
                      discovered: Some(discovered),
                      backoff_ms: first_backoff_ms,
                      fetch: Idle,
                    ),
                  )
                }
                False -> retry_discovery(state)
              }
            Error(_) -> retry_discovery(state)
          }
        }
      }
    RefreshKeys(kid, reply) ->
      case state.fetch, state.discovered {
        _, None -> {
          process.send(reply, None)
          actor.continue(state)
        }
        // Join the refresh in flight.
        FetchingKeys(worker, waiters), _ ->
          actor.continue(
            State(..state, fetch: FetchingKeys(worker, [reply, ..waiters])),
          )
        _, Some(discovered) -> {
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
          let allowed =
            new_kid || now - state.last_key_refresh >= key_refresh_interval_ms
          case allowed, state.fetch {
            True, Idle -> {
              let uri = discovered.jwks_uri
              let policy = state.policy
              let worker =
                provider_fetch.start(
                  state.self,
                  fn() { load_keys(uri, policy) },
                  KeysLoaded,
                )
              actor.continue(
                State(
                  ..state,
                  last_key_refresh: now,
                  attempted_kids:,
                  fetch: FetchingKeys(worker, [reply]),
                ),
              )
            }
            // Throttled, or a reload is already fetching fresh keys.
            _, _ -> {
              process.send(reply, snapshot(state))
              actor.continue(State(..state, attempted_kids:))
            }
          }
        }
      }
    KeysLoaded(pid, result) ->
      case finish_background(state, pid) {
        False -> actor.continue(state)
        True -> {
          let state = case result, state.discovered {
            Ok(keys), Some(discovered) ->
              State(..state, discovered: Some(Discovered(..discovered, keys:)))
            _, _ -> state
          }
          case state.fetch {
            FetchingKeys(_, waiters) ->
              list.each(waiters, fn(waiter) {
                process.send(waiter, snapshot(state))
              })
            _ -> Nil
          }
          actor.continue(State(..state, fetch: Idle))
        }
      }
    Reload ->
      case state.fetch {
        Idle -> {
          let issuer = state.issuer
          let policy = state.policy
          let worker =
            provider_fetch.start(
              state.self,
              fn() { discover(issuer, policy, background_deadline(policy)) },
              Reloaded,
            )
          actor.continue(State(..state, fetch: Reloading(worker)))
        }
        // A fetch is in flight; try again shortly.
        _ -> {
          process.send_after(state.self, key_refresh_interval_ms, Reload)
          actor.continue(state)
        }
      }
    Reloaded(pid, result) ->
      case finish_background(state, pid) {
        False -> actor.continue(state)
        True -> {
          let state = case result {
            Ok(discovered) -> State(..state, discovered: Some(discovered))
            Error(_) -> state
          }
          let ttl = case state.discovered {
            Some(discovered) -> discovered.ttl_ms
            None -> first_backoff_ms
          }
          process.send_after(state.self, ttl, Reload)
          actor.continue(State(..state, fetch: Idle))
        }
      }
  }
}

fn complete_initial(state: State, outcome: Result(Metadata, Failure)) -> State {
  case state.initial {
    Completed(_) -> state
    Pending(waiter) -> {
      case waiter {
        Some(reply) -> process.send(reply, outcome)
        None -> Nil
      }
      State(..state, initial: Completed(outcome))
    }
  }
}

/// Only the manual startup caller observes this incarnation's first attempt.
pub fn await_initial(
  provider: Provider,
  timeout: Int,
) -> Result(Result(Metadata, Failure), call.CallError) {
  call.call(provider.subject, timeout, FirstDiscovery)
}

fn retry_discovery(state: State) -> actor.Next(State, Message) {
  process.send_after(state.self, state.backoff_ms, Discover)
  actor.continue(
    State(
      ..state,
      fetch: Idle,
      backoff_ms: int.min(state.backoff_ms * 2, max_backoff_ms),
    ),
  )
}

pub fn snapshot_of(provider: Provider) -> Result(Snapshot, Failure) {
  case call.call(provider.subject, provider.timeout, Get) {
    Ok(Some(snapshot)) -> Ok(snapshot)
    _ -> Error(protocol.NotReady)
  }
}

pub fn refresh_keys(
  provider: Provider,
  kid: Option(String),
) -> Result(Snapshot, Failure) {
  case call.call(provider.subject, provider.timeout, RefreshKeys(kid, _)) {
    Ok(Some(snapshot)) -> Ok(snapshot)
    _ -> Error(protocol.NotReady)
  }
}

/// The same provider with calls bounded by `timeout` milliseconds.
pub fn within(provider: Provider, timeout: Int) -> Provider {
  Provider(..provider, timeout: int.max(1, int.min(provider.timeout, timeout)))
}

@external(erlang, "erlang", "monotonic_time")
fn monotonic_time(unit: atom.Atom) -> Int

fn monotonic_ms() -> Int {
  monotonic_time(atom.create("millisecond"))
}
