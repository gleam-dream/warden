//// Warden's bounded HTTPS client.
////
//// Owned decisions (decision D11, probe P2):
//// - HTTPS only, peer and hostname verification against explicit trust
////   anchors; verification cannot be disabled.
//// - DNS is resolved once; every address must pass the destination policy
////   and the connection goes to an address from that answer, with TLS still
////   verified against the original host name.
//// - Redirects are returned, never followed.
//// - Response head and body sizes are bounded while reading; a declared
////   `content-length` above the limit is refused before reading the body.
//// - One deadline covers resolution, connection, send and receive.
//// - Failures carry transmission evidence: `NotSent` only when no request
////   byte can have reached the peer.
////
//// OTP `ssl`, `inet` and `public_key` are called directly; there is no
//// handwritten Erlang module. Errors never carry request or response
//// content.

import exception
import gleam/bit_array
import gleam/bool
import gleam/bytes_tree.{type BytesTree}
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/erlang/atom.{type Atom}
import gleam/erlang/charlist.{type Charlist}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri
import sinal
import warden/observation

// ---------------------------------------------------------------------------
// Public types

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
  InvalidTlsConfiguration
  NoTrustAnchors
  Timeout
  SendFailed
  ReceiveFailed
  MalformedResponse
  HeadersTooLarge
  BodyTooLarge
  TruncatedBody
  UnsupportedTransferEncoding
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

// ---------------------------------------------------------------------------
// Entry point

pub fn send(policy: Policy, request: Request) -> Result(Response, Failure) {
  let start = monotonic_ms()
  let deadline = start + policy.timeout_ms
  let result = case exception.rescue(fn() { run(policy, request, deadline) }) {
    Ok(result) -> result
    // An unexpected exception after connecting cannot prove no-send.
    Error(_) -> Error(Failure(Sent, InternalError))
  }
  observe(request, result, start)
  result
}

type Target {
  Target(host: String, port: Int, target: String)
}

fn run(
  policy: Policy,
  request: Request,
  deadline: Int,
) -> Result(Response, Failure) {
  use target <- result.try(parse_target(request.url))
  use <- bool.guard(
    !host_allowed(target.host, policy.allowed_hosts),
    not_sent(DestinationRejected),
  )
  use address <- result.try(resolve(target.host, policy, deadline))
  use bytes <- result.try(encode_request(request, target))
  use socket <- result.try(connect(address, target, policy, deadline))
  exception.defer(fn() { ssl_close(socket) }, fn() {
    case
      decode.run(ssl_send(socket, bytes), atom.decoder())
      |> result.map(atom.to_string)
    {
      Ok("ok") -> receive_response(socket, request.method, policy, deadline)
      _ -> Error(Failure(Sent, SendFailed))
    }
  })
}

fn not_sent(class: Class) -> Result(a, Failure) {
  Error(Failure(NotSent, class))
}

fn sent(class: Class) -> Result(a, Failure) {
  Error(Failure(Sent, class))
}

// ---------------------------------------------------------------------------
// Request shape

fn parse_target(url: String) -> Result(Target, Failure) {
  case uri.parse(url) {
    Ok(uri.Uri(
      scheme: Some(scheme),
      userinfo:,
      host: Some(host),
      port:,
      path:,
      query:,
      fragment:,
    )) ->
      case string.lowercase(scheme), userinfo, fragment, host {
        "https", None, None, host if host != "" -> {
          let port = option.unwrap(port, 443)
          let path = case path {
            "" -> "/"
            p -> p
          }
          let target = case query {
            Some(q) -> path <> "?" <> q
            None -> path
          }
          case port > 0 && port < 65_536 {
            True -> Ok(Target(host: string.lowercase(host), port:, target:))
            False -> not_sent(InvalidDestination)
          }
        }
        "https", _, _, _ -> not_sent(InvalidDestination)
        _, _, _, _ -> not_sent(InsecureScheme)
      }
    _ -> not_sent(InvalidDestination)
  }
}

fn host_allowed(host: String, allowed: Option(List(String))) -> Bool {
  case allowed {
    None -> True
    Some(hosts) -> list.contains(list.map(hosts, string.lowercase), host)
  }
}

fn encode_request(
  request: Request,
  target: Target,
) -> Result(BytesTree, Failure) {
  let method = case request.method {
    Get -> "GET"
    Post -> "POST"
  }
  let host_header = case target.port {
    443 -> target.host
    port -> bracket(target.host) <> ":" <> int.to_string(port)
  }
  use headers <- result.try(
    request.headers
    |> list.filter(fn(h) {
      !list.contains(
        ["host", "content-length", "connection", "transfer-encoding"],
        string.lowercase(h.0),
      )
    })
    |> list.try_map(fn(h) {
      case clean(h.0) && clean(h.1) && h.0 != "" {
        True -> Ok(string.lowercase(h.0) <> ": " <> h.1 <> "\r\n")
        False -> not_sent(InvalidRequest)
      }
    }),
  )
  use <- bool.guard(!clean(target.target), not_sent(InvalidRequest))
  let length = case request.body {
    Some(body) ->
      "content-length: " <> int.to_string(bit_array.byte_size(body)) <> "\r\n"
    None -> ""
  }
  let head =
    method
    <> " "
    <> target.target
    <> " HTTP/1.1\r\nhost: "
    <> host_header
    <> "\r\nconnection: close\r\nuser-agent: warden\r\n"
    <> length
    <> string.concat(headers)
    <> "\r\n"
  Ok(
    bytes_tree.from_string(head)
    |> bytes_tree.append(option.unwrap(request.body, <<>>)),
  )
}

fn bracket(host: String) -> String {
  case string.contains(host, ":") && !string.starts_with(host, "[") {
    True -> "[" <> host <> "]"
    False -> host
  }
}

fn clean(value: String) -> Bool {
  !string.contains(value, "\r")
  && !string.contains(value, "\n")
  && !string.contains(value, "\u{0}")
}

// ---------------------------------------------------------------------------
// Destination policy

fn strip_brackets(host: String) -> String {
  case string.starts_with(host, "[") {
    True -> host |> string.drop_start(1) |> string.drop_end(1)
    False -> host
  }
}

fn resolve(
  host: String,
  policy: Policy,
  deadline: Int,
) -> Result(#(Address, Dynamic), Failure) {
  let bare = strip_brackets(host)
  let answer = case parse_strict_address(charlist.from_string(bare)) {
    Ok(literal) -> Ok([literal])
    Error(_) ->
      case policy.resolver {
        Some(resolver) ->
          resolver(bare, remaining(deadline))
          |> result.map(list.map(_, address_term))
        None -> {
          let lookup = fn(family) {
            case
              getaddrs(charlist.from_string(bare), family, remaining(deadline))
            {
              Ok(addresses) -> addresses
              Error(_) -> []
            }
          }
          Ok(list.append(
            lookup(atom.create("inet")),
            lookup(atom.create("inet6")),
          ))
        }
      }
  }
  case answer {
    Error(Nil) | Ok([]) -> not_sent(ResolutionFailed)
    Ok([first, ..] as terms) -> {
      let decoded = list.map(terms, decode_address)
      case
        list.all(decoded, fn(a) {
          case a {
            Ok(address) -> allowed(classify(address), policy)
            Error(Nil) -> False
          }
        }),
        decode_address(first)
      {
        True, Ok(address) -> Ok(#(address, first))
        _, _ -> not_sent(DestinationRejected)
      }
    }
  }
}

fn allowed(class: AddressClass, policy: Policy) -> Bool {
  case class {
    Public -> True
    Loopback -> policy.allow_loopback
    Private -> policy.allow_private
    Reserved -> False
  }
}

fn decode_address(term: Dynamic) -> Result(Address, Nil) {
  let byte = decode.int
  let v4 = {
    use a <- decode.field(0, byte)
    use b <- decode.field(1, byte)
    use c <- decode.field(2, byte)
    use d <- decode.field(3, byte)
    decode.success(Ipv4(a, b, c, d))
  }
  let v6 = {
    use a <- decode.field(0, byte)
    use b <- decode.field(1, byte)
    use c <- decode.field(2, byte)
    use d <- decode.field(3, byte)
    use e <- decode.field(4, byte)
    use f <- decode.field(5, byte)
    use g <- decode.field(6, byte)
    use h <- decode.field(7, byte)
    decode.success(Ipv6(a, b, c, d, e, f, g, h))
  }
  case tuple_size(term) {
    Ok(4) -> decode.run(term, v4) |> result.replace_error(Nil)
    Ok(8) -> decode.run(term, v6) |> result.replace_error(Nil)
    _ -> Error(Nil)
  }
  |> result.try(fn(address) {
    case in_range(address) {
      True -> Ok(address)
      False -> Error(Nil)
    }
  })
}

fn in_range(address: Address) -> Bool {
  case address {
    Ipv4(a, b, c, d) -> list.all([a, b, c, d], fn(x) { x >= 0 && x <= 255 })
    Ipv6(a, b, c, d, e, f, g, h) ->
      list.all([a, b, c, d, e, f, g, h], fn(x) { x >= 0 && x <= 0xFFFF })
  }
}

fn address_term(address: Address) -> Dynamic {
  case address {
    Ipv4(a, b, c, d) -> to_dynamic(#(a, b, c, d))
    Ipv6(a, b, c, d, e, f, g, h) -> to_dynamic(#(a, b, c, d, e, f, g, h))
  }
}

/// Classify an address. Loopback, private (RFC 1918, RFC 6598, unique
/// local) and reserved ranges; IPv4-mapped and NAT64 IPv6 addresses are
/// classified by their embedded IPv4 address.
pub fn classify(address: Address) -> AddressClass {
  case address {
    Ipv4(0, _, _, _) -> Reserved
    Ipv4(10, _, _, _) -> Private
    Ipv4(100, b, _, _) if b >= 64 && b <= 127 -> Private
    Ipv4(127, _, _, _) -> Loopback
    Ipv4(169, 254, _, _) -> Reserved
    Ipv4(172, b, _, _) if b >= 16 && b <= 31 -> Private
    Ipv4(192, 0, 0, _) -> Reserved
    Ipv4(192, 0, 2, _) -> Reserved
    Ipv4(192, 88, 99, _) -> Reserved
    Ipv4(192, 168, _, _) -> Private
    Ipv4(198, 18, _, _) | Ipv4(198, 19, _, _) -> Reserved
    Ipv4(198, 51, 100, _) -> Reserved
    Ipv4(203, 0, 113, _) -> Reserved
    Ipv4(a, _, _, _) if a >= 224 -> Reserved
    Ipv4(_, _, _, _) -> Public
    Ipv6(0, 0, 0, 0, 0, 0, 0, 0) -> Reserved
    Ipv6(0, 0, 0, 0, 0, 0, 0, 1) -> Loopback
    Ipv6(0, 0, 0, 0, 0, 0xFFFF, hi, lo) -> classify(embedded(hi, lo))
    Ipv6(0x64, 0xFF9B, 0, 0, 0, 0, hi, lo) -> classify(embedded(hi, lo))
    Ipv6(0x100, 0, 0, 0, _, _, _, _) -> Reserved
    Ipv6(0x2001, 0xDB8, _, _, _, _, _, _) -> Reserved
    Ipv6(0x2002, _, _, _, _, _, _, _) -> Reserved
    Ipv6(a, _, _, _, _, _, _, _) ->
      case
        int.bitwise_and(a, 0xFE00) == 0xFC00,
        int.bitwise_and(a, 0xFFC0) == 0xFE80,
        int.bitwise_and(a, 0xFF00) == 0xFF00,
        int.bitwise_and(a, 0xE000) == 0x2000
      {
        True, _, _, _ -> Private
        _, True, _, _ -> Reserved
        _, _, True, _ -> Reserved
        _, _, _, True -> Public
        _, _, _, _ -> Reserved
      }
  }
}

fn embedded(hi: Int, lo: Int) -> Address {
  Ipv4(
    int.bitwise_shift_right(hi, 8),
    int.bitwise_and(hi, 255),
    int.bitwise_shift_right(lo, 8),
    int.bitwise_and(lo, 255),
  )
}

// ---------------------------------------------------------------------------
// TLS connection

fn connect(
  address: #(Address, Dynamic),
  target: Target,
  policy: Policy,
  deadline: Int,
) -> Result(Socket, Failure) {
  use cacerts <- result.try(case policy.trust {
    Anchors([_, ..] as certs) -> Ok(certs)
    Anchors([]) -> not_sent(NoTrustAnchors)
    SystemTrust ->
      case exception.rescue(cacerts_get) {
        Ok([_, ..] as certs) -> Ok(certs)
        _ -> not_sent(NoTrustAnchors)
      }
  })
  let is_literal =
    parse_strict_address(charlist.from_string(strip_brackets(target.host)))
    |> result.is_ok
  let sni = case is_literal {
    True -> option(a("server_name_indication"), a("disable"))
    False ->
      option(a("server_name_indication"), charlist.from_string(target.host))
  }
  let options = [
    to_dynamic(a("binary")),
    option(a("active"), False),
    option(a("packet"), a("raw")),
    option(a("verify"), a("verify_peer")),
    option(a("cacerts"), cacerts),
    option(a("depth"), 10),
    option(a("versions"), [a("tlsv1.3"), a("tlsv1.2")]),
    option(a("log_level"), a("warning")),
    option(a("customize_hostname_check"), [
      #(a("match_fun"), hostname_match_fun(a("https"))),
    ]),
    sni,
  ]
  case remaining(deadline) {
    0 -> not_sent(Timeout)
    time ->
      // The handshake completes before any request byte is written, so
      // every failure here is pre-transmission.
      ssl_connect(address.1, target.port, options, time)
      |> result.map_error(fn(reason) { Failure(NotSent, connect_class(reason)) })
  }
}

fn connect_class(reason: Dynamic) -> Class {
  case decode.run(reason, atom.decoder()) {
    Ok(name) ->
      case atom.to_string(name) {
        "timeout" -> Timeout
        "econnrefused" -> ConnectionRefused
        _ -> ConnectionFailed
      }
    Error(_) ->
      case decode.run(reason, decode.at([0], atom.decoder())) {
        Ok(tag) ->
          case atom.to_string(tag) {
            "tls_alert" -> TlsRejected
            "options" -> InvalidTlsConfiguration
            _ -> ConnectionFailed
          }
        Error(_) -> ConnectionFailed
      }
  }
}

fn a(name: String) -> Atom {
  atom.create(name)
}

fn option(name: Atom, value: v) -> Dynamic {
  to_dynamic(#(name, value))
}

// ---------------------------------------------------------------------------
// Response

const max_interim = 5

const max_chunk_line = 1024

fn receive_response(
  socket: Socket,
  method: Method,
  policy: Policy,
  deadline: Int,
) -> Result(Response, Failure) {
  use #(status, headers, rest) <- result.try(read_final_head(
    socket,
    policy,
    deadline,
    <<>>,
    max_interim,
  ))
  use body <- result.try(read_body(
    socket,
    method,
    status,
    headers,
    rest,
    policy,
    deadline,
  ))
  Ok(Response(status:, headers:, body:))
}

fn read_final_head(
  socket: Socket,
  policy: Policy,
  deadline: Int,
  buffer: BitArray,
  interim: Int,
) -> Result(#(Int, List(#(String, String)), BitArray), Failure) {
  use #(head, rest) <- result.try(read_head(socket, policy, deadline, buffer))
  use #(status, headers) <- result.try(parse_head(head, policy))
  case status < 200, interim {
    True, 0 -> sent(MalformedResponse)
    True, _ -> read_final_head(socket, policy, deadline, rest, interim - 1)
    False, _ -> Ok(#(status, headers, rest))
  }
}

/// Accumulate until the blank line ending the head, bounded by the header
/// byte limit.
fn read_head(
  socket: Socket,
  policy: Policy,
  deadline: Int,
  buffer: BitArray,
) -> Result(#(BitArray, BitArray), Failure) {
  case split_once(buffer, <<"\r\n\r\n":utf8>>) {
    Ok(parts) -> Ok(parts)
    Error(Nil) ->
      case bit_array.byte_size(buffer) > policy.max_header_bytes {
        True -> sent(HeadersTooLarge)
        False ->
          case recv(socket, deadline) {
            Ok(data) ->
              read_head(
                socket,
                policy,
                deadline,
                bit_array.append(buffer, data),
              )
            Error(Closed) -> sent(MalformedResponse)
            Error(Other(class)) -> sent(class)
          }
      }
  }
}

fn parse_head(
  head: BitArray,
  policy: Policy,
) -> Result(#(Int, List(#(String, String))), Failure) {
  use text <- result.try(
    bit_array.to_string(head)
    |> result.replace_error(Failure(Sent, MalformedResponse)),
  )
  case string.split(text, "\r\n") {
    [status_line, ..lines] -> {
      use status <- result.try(parse_status(status_line))
      use <- bool.guard(
        list.length(lines) > policy.max_headers,
        sent(HeadersTooLarge),
      )
      use headers <- result.try(list.try_map(lines, parse_header))
      Ok(#(status, headers))
    }
    [] -> sent(MalformedResponse)
  }
}

fn parse_status(line: String) -> Result(Int, Failure) {
  case string.split(line, " ") {
    ["HTTP/1." <> _, code, ..] ->
      case int.parse(code) {
        Ok(status) if status >= 100 && status <= 599 -> Ok(status)
        _ -> sent(MalformedResponse)
      }
    _ -> sent(MalformedResponse)
  }
}

fn parse_header(line: String) -> Result(#(String, String), Failure) {
  case string.split_once(line, ":") {
    Ok(#(name, value)) ->
      case
        name != ""
        && !string.contains(name, " ")
        && !string.contains(name, "\t")
      {
        True -> Ok(#(string.lowercase(name), string.trim(value)))
        False -> sent(MalformedResponse)
      }
    Error(Nil) -> sent(MalformedResponse)
  }
}

fn read_body(
  socket: Socket,
  _method: Method,
  status: Int,
  headers: List(#(String, String)),
  rest: BitArray,
  policy: Policy,
  deadline: Int,
) -> Result(BitArray, Failure) {
  let values = fn(name) {
    list.filter_map(headers, fn(h) {
      case h.0 == name {
        True -> Ok(h.1)
        False -> Error(Nil)
      }
    })
  }
  use <- bool.guard(status == 204 || status == 304, Ok(<<>>))
  use _ <- result.try(case values("content-encoding") {
    [] -> Ok(Nil)
    [value] ->
      case string.lowercase(value) {
        "identity" -> Ok(Nil)
        _ -> sent(UnsupportedContentEncoding)
      }
    _ -> sent(UnsupportedContentEncoding)
  })
  case values("transfer-encoding"), values("content-length") {
    [], [] -> read_until_close(socket, policy.max_body, deadline, rest)
    [], lengths ->
      case lengths |> list.map(int.parse) |> list.unique {
        [Ok(length)] if length > policy.max_body -> sent(BodyTooLarge)
        [Ok(length)] if length >= 0 -> read_exact(socket, length, deadline, rest)
        _ -> sent(MalformedResponse)
      }
    [encoding], [] ->
      case string.lowercase(encoding) {
        "chunked" -> read_chunked(socket, policy.max_body, deadline, rest, <<>>)
        _ -> sent(UnsupportedTransferEncoding)
      }
    _, _ -> sent(MalformedResponse)
  }
}

fn read_exact(
  socket: Socket,
  length: Int,
  deadline: Int,
  buffer: BitArray,
) -> Result(BitArray, Failure) {
  let size = bit_array.byte_size(buffer)
  case size >= length {
    True ->
      case size == length {
        True -> Ok(buffer)
        False -> sent(MalformedResponse)
      }
    False ->
      case recv(socket, deadline) {
        Ok(data) ->
          read_exact(socket, length, deadline, bit_array.append(buffer, data))
        Error(Closed) -> sent(TruncatedBody)
        Error(Other(class)) -> sent(class)
      }
  }
}

fn read_until_close(
  socket: Socket,
  max: Int,
  deadline: Int,
  buffer: BitArray,
) -> Result(BitArray, Failure) {
  case bit_array.byte_size(buffer) > max {
    True -> sent(BodyTooLarge)
    False ->
      case recv(socket, deadline) {
        Ok(data) ->
          read_until_close(
            socket,
            max,
            deadline,
            bit_array.append(buffer, data),
          )
        Error(Closed) -> Ok(buffer)
        Error(Other(class)) -> sent(class)
      }
  }
}

/// Chunked decoding over a byte buffer; the decoded body and the pending
/// buffer are both bounded by the body limit plus one read.
fn read_chunked(
  socket: Socket,
  max: Int,
  deadline: Int,
  buffer: BitArray,
  body: BitArray,
) -> Result(BitArray, Failure) {
  case split_once(buffer, <<"\r\n":utf8>>) {
    Ok(#(line, rest)) -> {
      let decoded = bit_array.byte_size(body)
      case chunk_size(line) {
        Ok(0) -> finish_trailers(socket, deadline, rest, body)
        Ok(size) if size + decoded > max -> sent(BodyTooLarge)
        Ok(size) -> chunk_data(socket, max, deadline, size, rest, body)
        Error(Nil) -> sent(MalformedResponse)
      }
    }
    Error(Nil) ->
      case bit_array.byte_size(buffer) > max_chunk_line {
        True -> sent(MalformedResponse)
        False ->
          case recv(socket, deadline) {
            Ok(data) ->
              read_chunked(
                socket,
                max,
                deadline,
                bit_array.append(buffer, data),
                body,
              )
            Error(Closed) -> sent(TruncatedBody)
            Error(Other(class)) -> sent(class)
          }
      }
  }
}

fn chunk_data(
  socket: Socket,
  max: Int,
  deadline: Int,
  size: Int,
  buffer: BitArray,
  body: BitArray,
) -> Result(BitArray, Failure) {
  case buffer {
    <<chunk:bytes-size(size), "\r\n":utf8, rest:bytes>> ->
      read_chunked(socket, max, deadline, rest, bit_array.append(body, chunk))
    _ ->
      case bit_array.byte_size(buffer) >= size + 2 {
        True -> sent(MalformedResponse)
        False ->
          case recv(socket, deadline) {
            Ok(data) ->
              chunk_data(
                socket,
                max,
                deadline,
                size,
                bit_array.append(buffer, data),
                body,
              )
            Error(Closed) -> sent(TruncatedBody)
            Error(Other(class)) -> sent(class)
          }
      }
  }
}

fn chunk_size(line: BitArray) -> Result(Int, Nil) {
  use text <- result.try(bit_array.to_string(line))
  let hex = case string.split_once(text, ";") {
    Ok(#(hex, _extensions)) -> hex
    Error(Nil) -> text
  }
  let hex = string.trim(hex)
  case string.length(hex) {
    n if n > 0 && n <= 8 -> int.base_parse(hex, 16)
    _ -> Error(Nil)
  }
}

/// Trailers after the last chunk are discarded within the chunk-line bound.
fn finish_trailers(
  socket: Socket,
  deadline: Int,
  buffer: BitArray,
  body: BitArray,
) -> Result(BitArray, Failure) {
  case buffer {
    <<"\r\n":utf8, _:bytes>> -> Ok(body)
    _ ->
      case split_once(buffer, <<"\r\n\r\n":utf8>>) {
        Ok(_) -> Ok(body)
        Error(Nil) ->
          case bit_array.byte_size(buffer) > max_chunk_line {
            True -> sent(MalformedResponse)
            False ->
              case recv(socket, deadline) {
                Ok(data) ->
                  finish_trailers(
                    socket,
                    deadline,
                    bit_array.append(buffer, data),
                    body,
                  )
                Error(Closed) -> Ok(body)
                Error(Other(class)) -> sent(class)
              }
          }
      }
  }
}

type RecvError {
  Closed
  Other(Class)
}

fn recv(socket: Socket, deadline: Int) -> Result(BitArray, RecvError) {
  case remaining(deadline) {
    0 -> Error(Other(Timeout))
    time ->
      ssl_recv(socket, 0, time)
      |> result.map_error(fn(reason) {
        case decode.run(reason, atom.decoder()) {
          Ok(name) ->
            case atom.to_string(name) {
              "timeout" -> Other(Timeout)
              "closed" -> Closed
              _ -> Other(ReceiveFailed)
            }
          Error(_) -> Other(ReceiveFailed)
        }
      })
  }
}

// ---------------------------------------------------------------------------
// Helpers

fn remaining(deadline: Int) -> Int {
  int.max(0, deadline - monotonic_ms())
}

fn split_once(
  bits: BitArray,
  pattern: BitArray,
) -> Result(#(BitArray, BitArray), Nil) {
  case binary_split(bits, pattern) {
    [before, after] -> Ok(#(before, after))
    _ -> Error(Nil)
  }
}

/// Observation carries only method, host, path, status or failure class and
/// duration (`observation.http_request`). Queries, headers and bodies are
/// never observed. An emission failure never affects the request.
fn observe(
  request: Request,
  result: Result(Response, Failure),
  start: Int,
) -> Nil {
  let #(host, path) = case uri.parse(request.url) {
    Ok(uri.Uri(host: Some(host), path:, ..)) -> #(host, path)
    _ -> #("", "")
  }
  let outcome = case result {
    Ok(response) -> observation.Status(response.status)
    Error(Failure(stage:, class:)) ->
      observation.Failed(sent: stage == Sent, class: class_name(class))
  }
  let method = case request.method {
    Get -> observation.Get
    Post -> observation.Post
  }
  let _ =
    sinal.emit(
      observation.http_request(),
      observation.HttpMeasurements(duration_ms: monotonic_ms() - start),
      observation.HttpRequest(method:, host:, path:, outcome:),
    )
  Nil
}

/// Closed snake_case name of a failure class (observation, oidcc adapter).
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
    InvalidTlsConfiguration -> "invalid_tls_configuration"
    NoTrustAnchors -> "no_trust_anchors"
    Timeout -> "timeout"
    SendFailed -> "send_failed"
    ReceiveFailed -> "receive_failed"
    MalformedResponse -> "malformed_response"
    HeadersTooLarge -> "headers_too_large"
    BodyTooLarge -> "body_too_large"
    TruncatedBody -> "truncated_body"
    UnsupportedTransferEncoding -> "unsupported_transfer_encoding"
    UnsupportedContentEncoding -> "unsupported_content_encoding"
    InternalError -> "internal_error"
  }
}

// ---------------------------------------------------------------------------
// OTP bindings (no handwritten Erlang)

pub type Socket

@external(erlang, "ssl", "connect")
fn ssl_connect(
  address: Dynamic,
  port: Int,
  options: List(Dynamic),
  timeout: Int,
) -> Result(Socket, Dynamic)

@external(erlang, "ssl", "send")
fn ssl_send(socket: Socket, data: BytesTree) -> Dynamic

@external(erlang, "ssl", "recv")
fn ssl_recv(
  socket: Socket,
  length: Int,
  timeout: Int,
) -> Result(BitArray, Dynamic)

@external(erlang, "ssl", "close")
fn ssl_close(socket: Socket) -> Dynamic

@external(erlang, "inet", "getaddrs")
fn getaddrs(
  host: Charlist,
  family: Atom,
  timeout: Int,
) -> Result(List(Dynamic), Dynamic)

@external(erlang, "inet", "parse_strict_address")
fn parse_strict_address(host: Charlist) -> Result(Dynamic, Dynamic)

@external(erlang, "public_key", "cacerts_get")
fn cacerts_get() -> List(BitArray)

@external(erlang, "public_key", "pkix_verify_hostname_match_fun")
fn hostname_match_fun(protocol: Atom) -> Dynamic

@external(erlang, "binary", "split")
fn binary_split(subject: BitArray, pattern: BitArray) -> List(BitArray)

@external(erlang, "erlang", "tuple_size")
fn tuple_size_raw(term: Dynamic) -> Int

fn tuple_size(term: Dynamic) -> Result(Int, Nil) {
  case exception.rescue(fn() { tuple_size_raw(term) }) {
    Ok(size) -> Ok(size)
    Error(_) -> Error(Nil)
  }
}

@external(erlang, "gleam_stdlib", "identity")
fn to_dynamic(value: a) -> Dynamic

@external(erlang, "erlang", "monotonic_time")
fn monotonic_time(unit: Atom) -> Int

fn monotonic_ms() -> Int {
  monotonic_time(a("millisecond"))
}
