//// A small HTTPS/1.1 server on loopback over OTP `ssl`, for
//// `warden/testing`. Each connection serves one request and closes. Heads
//// are limited to 64 KiB and bodies to 1 MiB; anything else is answered 400.

import gleam/bit_array
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/erlang/atom.{type Atom}
import gleam/erlang/process
import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import warden/internal/test_pki.{type Pki}

pub type Server {
  Server(port: Int, acceptor: process.Pid, listen: Dynamic)
}

const max_head = 65_536

const max_body = 1_048_576

pub fn start(
  pki: Pki,
  handle: fn(Request(String)) -> Response(String),
) -> Result(Server, Nil) {
  let a = atom.create
  let options = [
    to_dynamic(a("binary")),
    to_dynamic(#(a("active"), False)),
    to_dynamic(#(a("reuseaddr"), True)),
    to_dynamic(#(a("ip"), #(127, 0, 0, 1))),
    to_dynamic(#(a("cert"), pki.certificate)),
    to_dynamic(#(a("key"), pki.key)),
    to_dynamic(#(a("versions"), [a("tlsv1.3"), a("tlsv1.2")])),
  ]
  use _ <- result.try(ensure_ssl())
  use listen <- result.try(ok(ssl_listen(0, options)))
  use port <- result.try(
    ok(ssl_sockname(listen))
    |> result.try(fn(address) {
      decode.run(address, decode.at([1], decode.int))
      |> result.replace_error(Nil)
    }),
  )
  // Linked: the server goes when its owner does.
  let acceptor = process.spawn(fn() { accept_loop(listen, handle) })
  let _ = ssl_controlling_process(listen, acceptor)
  Ok(Server(port:, acceptor:, listen:))
}

pub fn stop(server: Server) -> Nil {
  process.unlink(server.acceptor)
  process.kill(server.acceptor)
  let _ = ssl_close(server.listen)
  Nil
}

fn ensure_ssl() -> Result(Nil, Nil) {
  case
    decode.run(
      ensure_all_started([atom.create("ssl")]),
      decode.at([0], atom.decoder()),
    )
  {
    Ok(tag) ->
      case atom.to_string(tag) {
        "ok" -> Ok(Nil)
        _ -> Error(Nil)
      }
    Error(_) -> Error(Nil)
  }
}

fn accept_loop(
  listen: Dynamic,
  handle: fn(Request(String)) -> Response(String),
) -> Nil {
  case ok(ssl_transport_accept(listen)) {
    Ok(transport) -> {
      // The connection process may use the socket only once it owns it.
      let ready = process.new_subject()
      let _ =
        process.spawn_unlinked(fn() {
          let go = process.new_subject()
          process.send(ready, go)
          case process.receive(go, 5000) {
            Ok(Nil) -> serve(transport, handle)
            Error(Nil) -> Nil
          }
        })
      case process.receive(ready, 5000) {
        Ok(go) -> {
          let _ =
            ssl_controlling_process(
              transport,
              process.subject_owner(go) |> unwrap_pid,
            )
          process.send(go, Nil)
        }
        Error(Nil) -> Nil
      }
      accept_loop(listen, handle)
    }
    Error(Nil) -> Nil
  }
}

fn serve(
  transport: Dynamic,
  handle: fn(Request(String)) -> Response(String),
) -> Nil {
  case ok(ssl_handshake(transport, 5000)) {
    Error(Nil) -> Nil
    Ok(socket) -> {
      let reply = case read_request(socket, <<>>) {
        Ok(request) -> handle(request)
        Error(Nil) -> response.new(400) |> response.set_body("")
      }
      let _ = ssl_send(socket, encode(reply))
      let _ = ssl_close(socket)
      Nil
    }
  }
}

fn read_request(
  socket: Dynamic,
  buffer: BitArray,
) -> Result(Request(String), Nil) {
  case split_head(buffer, 0) {
    Some(#(head, rest)) -> {
      use #(request, length) <- result.try(parse_head(head))
      use body <- result.try(read_body(socket, rest, length))
      use body <- result.map(bit_array.to_string(body))
      request.Request(..request, body:)
    }
    None ->
      case bit_array.byte_size(buffer) > max_head {
        True -> Error(Nil)
        False -> {
          use more <- result.try(recv(socket))
          read_request(socket, <<buffer:bits, more:bits>>)
        }
      }
  }
}

fn recv(socket: Dynamic) -> Result(BitArray, Nil) {
  ok(ssl_recv(socket, 0, 5000))
  |> result.try(fn(data) {
    decode.run(data, decode.bit_array) |> result.replace_error(Nil)
  })
}

fn read_body(
  socket: Dynamic,
  have: BitArray,
  length: Int,
) -> Result(BitArray, Nil) {
  case bit_array.byte_size(have) >= length {
    True -> bit_array.slice(have, 0, length)
    False -> {
      use more <- result.try(recv(socket))
      read_body(socket, <<have:bits, more:bits>>, length)
    }
  }
}

/// The head (before `\r\n\r\n`) and the bytes after it.
fn split_head(
  buffer: BitArray,
  at: Int,
) -> option.Option(#(BitArray, BitArray)) {
  case bit_array.slice(buffer, at, 4) {
    Ok(<<"\r\n\r\n":utf8>>) -> {
      let assert Ok(head) = bit_array.slice(buffer, 0, at)
      let size = bit_array.byte_size(buffer)
      let assert Ok(rest) = bit_array.slice(buffer, at + 4, size - at - 4)
      Some(#(head, rest))
    }
    Ok(_) -> split_head(buffer, at + 1)
    Error(Nil) -> None
  }
}

fn parse_head(head: BitArray) -> Result(#(Request(String), Int), Nil) {
  use text <- result.try(bit_array.to_string(head))
  case string.split(text, "\r\n") {
    [line, ..header_lines] -> {
      use #(method, target) <- result.try(case string.split(line, " ") {
        [method, target, "HTTP/1.1"] | [method, target, "HTTP/1.0"] ->
          Ok(#(method, target))
        _ -> Error(Nil)
      })
      use method <- result.try(http.parse_method(method))
      let headers =
        list.filter_map(header_lines, fn(line) {
          case string.split_once(line, ":") {
            Ok(#(name, value)) ->
              Ok(#(string.lowercase(string.trim(name)), string.trim(value)))
            Error(Nil) -> Error(Nil)
          }
        })
      let #(path, query) = case string.split_once(target, "?") {
        Ok(#(path, query)) -> #(path, Some(query))
        Error(Nil) -> #(target, None)
      }
      let length = case list.key_find(headers, "content-length") {
        Ok(value) -> int.parse(value) |> result.unwrap(-1)
        Error(Nil) -> 0
      }
      case length < 0 || length > max_body {
        True -> Error(Nil)
        False ->
          Ok(#(
            request.Request(
              method:,
              headers:,
              body: "",
              scheme: http.Https,
              host: "localhost",
              port: None,
              path:,
              query:,
            ),
            length,
          ))
      }
    }
    [] -> Error(Nil)
  }
}

fn encode(reply: Response(String)) -> BitArray {
  let body = bit_array.from_string(reply.body)
  let headers =
    reply.headers
    |> list.filter(fn(h) { h.0 != "content-length" && h.0 != "connection" })
    |> list.map(fn(h) { h.0 <> ": " <> h.1 <> "\r\n" })
    |> string.concat
  let head =
    "HTTP/1.1 "
    <> int.to_string(reply.status)
    <> " X\r\n"
    <> headers
    <> "content-length: "
    <> int.to_string(bit_array.byte_size(body))
    <> "\r\nconnection: close\r\n\r\n"
  <<head:utf8, body:bits>>
}

fn unwrap_pid(owner: Result(process.Pid, Nil)) -> process.Pid {
  let assert Ok(pid) = owner
  pid
}

/// `{ok, Value}` as `Ok(Value)`, anything else as `Error(Nil)`.
fn ok(term: Dynamic) -> Result(Dynamic, Nil) {
  let tagged = {
    use tag <- decode.field(0, atom.decoder())
    use value <- decode.field(1, decode.dynamic)
    case atom.to_string(tag) {
      "ok" -> decode.success(value)
      _ -> decode.failure(value, "ok")
    }
  }
  decode.run(term, tagged) |> result.replace_error(Nil)
}

@external(erlang, "ssl", "listen")
fn ssl_listen(port: Int, options: List(Dynamic)) -> Dynamic

@external(erlang, "ssl", "sockname")
fn ssl_sockname(socket: Dynamic) -> Dynamic

@external(erlang, "ssl", "transport_accept")
fn ssl_transport_accept(socket: Dynamic) -> Dynamic

@external(erlang, "ssl", "handshake")
fn ssl_handshake(socket: Dynamic, timeout: Int) -> Dynamic

@external(erlang, "ssl", "controlling_process")
fn ssl_controlling_process(socket: Dynamic, pid: process.Pid) -> Dynamic

@external(erlang, "ssl", "recv")
fn ssl_recv(socket: Dynamic, length: Int, timeout: Int) -> Dynamic

@external(erlang, "ssl", "send")
fn ssl_send(socket: Dynamic, data: BitArray) -> Dynamic

@external(erlang, "ssl", "close")
fn ssl_close(socket: Dynamic) -> Dynamic

@external(erlang, "application", "ensure_all_started")
fn ensure_all_started(applications: List(Atom)) -> Dynamic

@external(erlang, "gleam_stdlib", "identity")
fn to_dynamic(value: a) -> Dynamic
