//// Warden's HTTPS transport over HTTP Gun (decision D11, adopted).
////
//// HTTP Gun owns the network: destination policy with DNS resolved once per
//// connection and every address checked, TLS against the original host (IP
//// literals against their IP SAN), framing, header and body limits, the
//// request deadline, connection readiness and reuse, submission evidence and
//// caller-mailbox hygiene.
////
//// Warden keeps application policy, before or after HTTP Gun parses:
//// - HTTPS only; no userinfo or fragment; header names and values without
////   CR, LF or NUL; request bodies of at most 64 KiB;
//// - a declared `content-length` above the body limit is refused before
////   reading; any non-identity `content-encoding` is refused;
//// - failures are mapped to closed classes; `NotSent` only when HTTP Gun
////   reports `NotSent`;
//// - observations (`telemetry.http_request`) carry only method, host,
////   path, status or failure reason, duration and the caller's correlation.
////
//// Requests run on the Warden client's supervised, shared HTTP Gun client
//// when the policy carries a pool; otherwise (startup discovery, tests) on a
//// one-shot client stopped after the request.

import exception
import gleam/bit_array
import gleam/erlang/atom.{type Atom}
import gleam/erlang/process
import gleam/http
import gleam/http/request as http_request
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/otp/supervision
import gleam/result
import gleam/string
import gleam/time/duration
import gleam/uri
import http_gun
import http_gun/body
import http_gun/config
import http_gun/deadline
import http_gun/destination
import http_gun/error
import sinal
import sinal/correlation.{type Correlation}
import warden/telemetry

pub type Trust {
  SystemTrust
  Anchors(List(BitArray))
}

pub type Policy {
  Policy(
    trust: Trust,
    allow_loopback: Bool,
    allow_private: Bool,
    allowed_hosts: Option(List(String)),
    timeout_ms: Int,
    max_body: Int,
    max_header_bytes: Int,
    max_headers: Int,
    /// Test seam: replaces DNS resolution. Never set in production config.
    resolver: Option(fn(String, Int) -> Result(List(Address), Nil)),
    /// The shared client to use; `None` uses a one-shot client.
    pool: Option(Pool),
    /// Carried into HTTP Gun's and Warden's request events.
    correlation: Option(Correlation),
  )
}

pub fn policy(trust: Trust) -> Policy {
  Policy(
    trust:,
    allow_loopback: False,
    allow_private: False,
    allowed_hosts: None,
    timeout_ms: 10_000,
    max_body: 1_048_576,
    max_header_bytes: 16_384,
    max_headers: 100,
    resolver: None,
    pool: None,
    correlation: None,
  )
}

pub type Method {
  Get
  Post
}

pub type Request {
  Request(
    method: Method,
    url: String,
    headers: List(#(String, String)),
    body: Option(BitArray),
  )
}

pub type Response {
  Response(status: Int, headers: List(#(String, String)), body: BitArray)
}

pub type Stage {
  NotSent
  Sent
}

pub type Class {
  InvalidRequest
  InvalidDestination
  InsecureScheme
  DestinationRejected
  ResolutionFailed
  ConnectionRefused
  ConnectionFailed
  TlsRejected
  NoTrustAnchors
  Timeout
  ReceiveFailed
  MalformedResponse
  HeadersTooLarge
  BodyTooLarge
  UnsupportedContentEncoding
  InternalError
}

pub type Failure {
  Failure(stage: Stage, class: Class)
}

pub type Address {
  Ipv4(Int, Int, Int, Int)
  Ipv6(Int, Int, Int, Int, Int, Int, Int, Int)
}

pub type AddressClass {
  Public
  Loopback
  Private
  Reserved
}

/// Largest request body Warden sends: its requests are small form posts.
pub const max_request_body = 65_536

// ---------------------------------------------------------------------------
// Shared client

/// A supervised HTTP Gun client, found by name so that a supervisor restart
/// (which starts a new client under the same name) is picked up.
pub opaque type Pool {
  Pool(name: process.Name(http_gun.Message))
}

pub fn new_pool() -> Pool {
  Pool(process.new_name("warden_http_pool"))
}

/// The supervisor child that owns the pool's HTTP Gun client.
pub fn pool_child(
  policy: Policy,
  pool: Pool,
) -> supervision.ChildSpecification(Nil) {
  http_gun.supervised(gun_config(policy), pool.name)
  |> supervision.map_data(fn(_) { Nil })
}

// ---------------------------------------------------------------------------
// Entry point

pub fn send(policy: Policy, request: Request) -> Result(Response, Failure) {
  let start = monotonic_ms()
  let result = case exception.rescue(fn() { run(policy, request) }) {
    Ok(result) -> result
    // An unexpected exception cannot prove that nothing was sent.
    Error(_) -> Error(Failure(Sent, InternalError))
  }
  observe(policy, request, result, start)
  result
}

fn run(policy: Policy, request: Request) -> Result(Response, Failure) {
  use _ <- result.try(check_url(request.url))
  use _ <- result.try(
    case
      list.all(request.headers, fn(h) { h.0 != "" && clean(h.0) && clean(h.1) })
    {
      True -> Ok(Nil)
      False -> not_sent(InvalidRequest)
    },
  )
  use _ <- result.try(case request.body {
    Some(body) ->
      case bit_array.byte_size(body) > max_request_body {
        True -> not_sent(InvalidRequest)
        False -> Ok(Nil)
      }
    None -> Ok(Nil)
  })
  use _ <- result.try(case policy.trust {
    Anchors([]) -> not_sent(NoTrustAnchors)
    _ -> Ok(Nil)
  })
  use req <- result.try(to_http(request))
  case policy.pool {
    // A stopped supervised client answers `ClientClosed` and `NotSent`.
    Some(pool) -> exchange(http_gun.named(pool.name), policy, req)
    None -> {
      use client <- result.try(
        http_gun.start(gun_config(policy))
        |> result.replace_error(Failure(NotSent, InternalError)),
      )
      exception.defer(fn() { http_gun.stop(client) }, fn() {
        exchange(client, policy, req)
      })
    }
  }
}

fn exchange(
  client: http_gun.Client,
  policy: Policy,
  req: http_request.Request(BitArray),
) -> Result(Response, Failure) {
  let budget = deadline.after(duration.milliseconds(policy.timeout_ms))
  let client = case policy.correlation {
    Some(correlation) -> http_gun.with_correlation(client, correlation)
    None -> client
  }
  http_gun.with_response(
    client |> http_gun.with_deadline(budget),
    req,
    from_gun,
    fn(response) {
      let headers = response.headers
      use _ <- result.try(content_encoding(headers))
      use _ <- result.try(declared_length(headers, policy.max_body))
      use collected <- result.try(
        body.collect(response.body, policy.max_body)
        |> result.map_error(from_gun),
      )
      Ok(Response(response.status, headers, collected.bytes))
    },
  )
}

/// The HTTP Gun configuration for a policy.
pub fn gun_config(policy: Policy) -> config.Config {
  let timeout = int.max(1, policy.timeout_ms)
  let allowed = destination.default()
  let allowed = case policy.allow_loopback {
    True -> destination.allow_loopback(allowed)
    False -> allowed
  }
  let allowed = case policy.allow_private {
    True -> destination.allow_private(allowed)
    False -> allowed
  }
  let allowed = case policy.allowed_hosts {
    Some(hosts) -> destination.only_hosts(allowed, hosts)
    None -> allowed
  }
  let configured =
    config.default()
    // Applications can filter Warden's HTTP Gun events by this label.
    |> config.with_label("warden")
    |> config.with_trust(case policy.trust {
      SystemTrust -> config.SystemTrust
      Anchors(ders) -> config.Anchors(ders)
    })
    // The request deadline bounds the whole exchange; connection setup,
    // pool checkout, idle reads and idle pooled connections keep HTTP Gun's
    // own tighter bounds (5 s, 5 s, 30 s, 60 s), so a saturated pool or a
    // dead connection fails before the request deadline.
    |> config.with_request_timeout(config.After(duration.milliseconds(timeout)))
    |> config.with_max_request_body_bytes(max_request_body)
    |> config.with_max_header_bytes(policy.max_header_bytes)
    |> config.with_max_header_count(policy.max_headers)
    |> config.with_max_response_body_bytes(policy.max_body)
    |> config.with_destination(allowed)
  case policy.resolver {
    Some(resolve) ->
      config.with_resolver(configured, fn(host, remaining) {
        resolve(host, duration.to_milliseconds(remaining))
        |> result.map(list.map(_, to_gun_address))
      })
    None -> configured
  }
}

// ---------------------------------------------------------------------------
// Request shape

fn check_url(url: String) -> Result(Nil, Failure) {
  case uri.parse(url) {
    Ok(uri.Uri(
      scheme: Some(scheme),
      userinfo:,
      host: Some(host),
      port:,
      fragment:,
      ..,
    )) ->
      case string.lowercase(scheme), userinfo, fragment, host {
        "https", None, None, host if host != "" ->
          case option.unwrap(port, 443) {
            p if p > 0 && p < 65_536 -> Ok(Nil)
            _ -> not_sent(InvalidDestination)
          }
        "https", _, _, _ -> not_sent(InvalidDestination)
        _, _, _, _ -> not_sent(InsecureScheme)
      }
    _ -> not_sent(InvalidDestination)
  }
}

fn to_http(
  request: Request,
) -> Result(http_request.Request(BitArray), Failure) {
  use req <- result.try(
    http_request.to(request.url)
    |> result.replace_error(Failure(NotSent, InvalidDestination)),
  )
  // Framing headers belong to HTTP Gun.
  let headers =
    request.headers
    |> list.filter(fn(h) {
      !list.contains(
        ["host", "content-length", "connection", "transfer-encoding"],
        string.lowercase(h.0),
      )
    })
    |> list.map(fn(h) { #(string.lowercase(h.0), h.1) })
  Ok(
    http_request.Request(
      ..req,
      method: case request.method {
        Get -> http.Get
        Post -> http.Post
      },
      headers: [#("user-agent", "warden"), ..headers],
      body: option.unwrap(request.body, <<>>),
    ),
  )
}

fn clean(value: String) -> Bool {
  !string.contains(value, "\r")
  && !string.contains(value, "\n")
  && !string.contains(value, "\u{0}")
}

// ---------------------------------------------------------------------------
// Response policy

fn content_encoding(headers: List(#(String, String))) -> Result(Nil, Failure) {
  case values(headers, "content-encoding") {
    [] -> Ok(Nil)
    [value] ->
      case string.lowercase(string.trim(value)) {
        "identity" -> Ok(Nil)
        _ -> Error(Failure(Sent, UnsupportedContentEncoding))
      }
    _ -> Error(Failure(Sent, UnsupportedContentEncoding))
  }
}

/// Refuse a declared length above the limit before reading the body;
/// HTTP Gun alone would read until the limit or the deadline.
fn declared_length(
  headers: List(#(String, String)),
  max_body: Int,
) -> Result(Nil, Failure) {
  case values(headers, "content-length") {
    [length, ..] ->
      case int.parse(length) {
        Ok(n) if n > max_body -> Error(Failure(Sent, BodyTooLarge))
        _ -> Ok(Nil)
      }
    [] -> Ok(Nil)
  }
}

fn values(headers: List(#(String, String)), name: String) -> List(String) {
  list.filter_map(headers, fn(h) {
    case string.lowercase(h.0) == name {
      True -> Ok(h.1)
      False -> Error(Nil)
    }
  })
}

// ---------------------------------------------------------------------------
// Failure mapping: submission evidence decides the stage. No class is finer
// than what HTTP Gun reports (decision D17).

fn from_gun(failure: error.Failure) -> Failure {
  let stage = case error.evidence(failure) {
    error.NotSent -> NotSent
    error.MaybeSent -> Sent
  }
  let class = case error.kind(failure) {
    error.InvalidInput -> InvalidRequest
    error.Refused -> DestinationRejected
    error.TimedOut -> Timeout
    error.Network -> network_class(error.reason(failure), stage)
    error.TooLarge -> limit_class(error.reason(failure))
    // `Kind` also holds the queue-full and closed-client reasons, which are
    // internal errors here. A pool wait that expires stays a timeout, as it
    // was while one deadline bounded the wait; that needs the reason.
    error.Unavailable ->
      case error.reason(failure) {
        error.PoolTimeout -> Timeout
        _ -> InternalError
      }
    error.CancelledLocally | error.Misuse | error.Playback -> InternalError
  }
  Failure(stage, class)
}

/// `Kind.Network` covers resolution and every transport cause; the cause
/// decides the class.
fn network_class(reason: error.Reason, stage: Stage) -> Class {
  case reason {
    error.ResolutionFailed -> ResolutionFailed
    error.ConnectionFailed(cause) | error.RequestFailed(cause) ->
      case cause {
        error.NameResolutionFailed -> ResolutionFailed
        error.ConnectionRefused -> ConnectionRefused
        error.CertificateRejected | error.TlsFailed -> TlsRejected
        error.TransportTimeout -> Timeout
        error.HeaderLimitReached -> HeadersTooLarge
        error.ProtocolError | error.UnexpectedProtocol -> MalformedResponse
        // A cause HTTP Gun adds later is as uncertain as `UnknownTransport`.
        _ -> uncertain_transport(stage)
      }
    _ -> uncertain_transport(stage)
  }
}

fn uncertain_transport(stage: Stage) -> Class {
  case stage {
    NotSent -> ConnectionFailed
    Sent -> ReceiveFailed
  }
}

/// `Kind.TooLarge` does not say which limit; the limit kind decides.
fn limit_class(reason: error.Reason) -> Class {
  case reason {
    error.LimitExceeded(kind:, ..) ->
      case kind {
        error.RequestBodyBytes
        | error.RequestHeaderBytes
        | error.RequestHeaderCount -> InvalidRequest
        error.ResponseHeaderBytes | error.ResponseHeaderCount -> HeadersTooLarge
        error.BufferedBytes | error.ResponseBodyBytes -> BodyTooLarge
        _ -> InternalError
      }
    _ -> InternalError
  }
}

fn not_sent(class: Class) -> Result(a, Failure) {
  Error(Failure(NotSent, class))
}

// ---------------------------------------------------------------------------
// Destination classification (HTTP Gun's table)

pub fn classify(address: Address) -> AddressClass {
  case destination.classify(to_gun_address(address)) {
    destination.Public -> Public
    destination.Loopback -> Loopback
    destination.Private -> Private
    destination.Reserved -> Reserved
  }
}

fn to_gun_address(address: Address) -> destination.Address {
  case address {
    Ipv4(a, b, c, d) -> destination.Ipv4(a, b, c, d)
    Ipv6(a, b, c, d, e, f, g, h) -> destination.Ipv6(a, b, c, d, e, f, g, h)
  }
}

// ---------------------------------------------------------------------------
// Observations

fn observe(
  policy: Policy,
  request: Request,
  result: Result(Response, Failure),
  start: Int,
) -> Nil {
  let #(host, path) = case uri.parse(request.url) {
    Ok(uri.Uri(host: Some(host), path:, ..)) -> #(host, path)
    _ -> #("", "")
  }
  let outcome = case result {
    Ok(response) -> telemetry.Status(response.status)
    Error(Failure(stage:, class:)) ->
      telemetry.Failed(
        evidence: case stage {
          Sent -> telemetry.MaybeSent
          NotSent -> telemetry.NotSent
        },
        reason: telemetry_reason(class),
      )
  }
  let method = case request.method {
    Get -> telemetry.Get
    Post -> telemetry.Post
  }
  sinal.emit(
    telemetry.http_request(),
    telemetry.HttpMeasurements(duration_ms: monotonic_ms() - start),
    telemetry.HttpRequest(
      method:,
      host:,
      path:,
      outcome:,
      correlation: policy.correlation,
    ),
  )
}

/// The telemetry reason of a failure class.
pub fn telemetry_reason(class: Class) -> telemetry.TransportReason {
  case class {
    InvalidDestination -> telemetry.InvalidDestination
    InsecureScheme -> telemetry.InsecureScheme
    DestinationRejected -> telemetry.DestinationRejected
    ResolutionFailed -> telemetry.ResolutionFailed
    ConnectionRefused -> telemetry.ConnectionRefused
    ConnectionFailed -> telemetry.ConnectionFailed
    TlsRejected -> telemetry.TlsRejected
    Timeout -> telemetry.Timeout
    ReceiveFailed -> telemetry.ReceiveFailed
    MalformedResponse -> telemetry.MalformedHttp
    HeadersTooLarge -> telemetry.ResponseHeadersTooLarge
    BodyTooLarge -> telemetry.ResponseTooLarge
    UnsupportedContentEncoding -> telemetry.UnsupportedContentEncoding
    InvalidRequest | NoTrustAnchors | InternalError ->
      telemetry.OtherTransportFailure
  }
}

/// Closed snake_case name of a failure class (observations, failure mapping).
pub fn class_name(class: Class) -> String {
  case class {
    InvalidRequest -> "invalid_request"
    InvalidDestination -> "invalid_destination"
    InsecureScheme -> "insecure_scheme"
    DestinationRejected -> "destination_rejected"
    ResolutionFailed -> "resolution_failed"
    ConnectionRefused -> "connection_refused"
    ConnectionFailed -> "connection_failed"
    TlsRejected -> "tls_rejected"
    NoTrustAnchors -> "no_trust_anchors"
    Timeout -> "timeout"
    ReceiveFailed -> "receive_failed"
    MalformedResponse -> "malformed_response"
    HeadersTooLarge -> "headers_too_large"
    BodyTooLarge -> "body_too_large"
    UnsupportedContentEncoding -> "unsupported_content_encoding"
    InternalError -> "internal_error"
  }
}

// ---------------------------------------------------------------------------
// OTP bindings

@external(erlang, "erlang", "monotonic_time")
fn monotonic_time(unit: Atom) -> Int

/// Monotonic milliseconds, for deadlines.
pub fn monotonic_ms() -> Int {
  monotonic_time(atom.create("millisecond"))
}
