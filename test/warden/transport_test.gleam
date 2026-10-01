//// The Gleam transport against real local TLS servers (probe P2, gate V6).

import gleam/bit_array
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import warden/internal/oidcc_transport
import warden/internal/transport.{Failure, Ipv4, Ipv6, NotSent, Sent}
import warden_test_support as support

fn policy() -> transport.Policy {
  transport.Policy(
    ..transport.policy(transport.Anchors([support.ca_der()])),
    allow_loopback: True,
    timeout_ms: 2000,
    max_body: 4096,
  )
}

fn get(policy: transport.Policy, url: String) {
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

fn with_server(
  cert: String,
  kind: support.Canned,
  run: fn(support.TestServer) -> a,
) -> a {
  let server = support.server_start(cert, kind)
  let result = run(server)
  support.server_stop(server)
  result
}

pub fn verified_tls_succeeds_test() {
  use s <- with_server("localhost", support.OkJson)
  let assert Ok(response) = get(policy(), support.server_url(s, "/x"))
  assert response.status == 200
  assert response.body == <<"{\"a\":1}":utf8>>
  assert list.key_find(response.headers, "content-type")
    == Ok("application/json")
}

pub fn loopback_rejected_by_default_before_connect_test() {
  use s <- with_server("localhost", support.OkJson)
  let p = transport.Policy(..policy(), allow_loopback: False)
  assert get(p, support.server_url(s, "/x"))
    == Error(Failure(NotSent, transport.DestinationRejected))
  support.sleep(50)
  assert support.server_requests(s) == 0
}

pub fn certificate_failures_are_rejected_before_send_test() {
  list.each(["wrong_host", "self_signed", "expired"], fn(cert) {
    use s <- with_server(cert, support.OkJson)
    assert #(cert, get(policy(), support.server_url(s, "/x")))
      == #(cert, Error(Failure(NotSent, transport.TlsRejected)))
  })
}

pub fn system_trust_does_not_accept_the_test_ca_test() {
  use s <- with_server("localhost", support.OkJson)
  let p = transport.Policy(..policy(), trust: transport.SystemTrust)
  assert get(p, support.server_url(s, "/x"))
    == Error(Failure(NotSent, transport.TlsRejected))
}

pub fn redirect_is_returned_not_followed_test() {
  use s <- with_server("localhost", support.Redirect)
  let assert Ok(response) = get(policy(), support.server_url(s, "/x"))
  assert response.status == 302
  support.sleep(50)
  assert support.server_requests(s) == 1
}

pub fn response_bounds_test() {
  let cases = [
    #(support.DeclaredOversize, transport.BodyTooLarge),
    #(support.EndlessChunked, transport.BodyTooLarge),
    #(support.CloseDelimitedOversize, transport.BodyTooLarge),
    #(support.ManyHeaders, transport.HeadersTooLarge),
    #(support.BigHeaderLine, transport.HeadersTooLarge),
    #(support.Gzip, transport.UnsupportedContentEncoding),
    #(support.Truncated, transport.TruncatedBody),
    #(support.BadStatus, transport.MalformedResponse),
  ]
  list.each(cases, fn(c) {
    use s <- with_server("localhost", c.0)
    assert #(c.0, get(policy(), support.server_url(s, "/x")))
      == #(c.0, Error(Failure(Sent, c.1)))
  })
}

pub fn chunked_and_interim_responses_decode_test() {
  {
    use s <- with_server("localhost", support.ChunkedOk)
    let assert Ok(response) = get(policy(), support.server_url(s, "/x"))
    assert response.body == <<"{\"a\":1}":utf8>>
  }
  use s <- with_server("localhost", support.Interim)
  let assert Ok(response) = get(policy(), support.server_url(s, "/x"))
  assert response.status == 200
  assert response.body == <<"ok":utf8>>
}

pub fn deadline_covers_the_exchange_test() {
  use s <- with_server("localhost", support.Slow)
  let p = transport.Policy(..policy(), timeout_ms: 300)
  assert get(p, support.server_url(s, "/x"))
    == Error(Failure(Sent, transport.Timeout))
}

pub fn request_shape_is_validated_before_send_test() {
  assert get(policy(), "http://localhost:1/x")
    == Error(Failure(NotSent, transport.InsecureScheme))
  assert get(policy(), "https://user:pw@localhost:1/x")
    == Error(Failure(NotSent, transport.InvalidDestination))
  assert get(policy(), "https://localhost:1/x#f")
    == Error(Failure(NotSent, transport.InvalidDestination))
  use s <- with_server("localhost", support.OkJson)
  assert transport.send(
      policy(),
      transport.Request(
        transport.Get,
        support.server_url(s, "/x"),
        [#("x-evil", "a\r\nhost: other")],
        None,
      ),
    )
    == Error(Failure(NotSent, transport.InvalidRequest))
}

pub fn connection_refused_is_not_sent_test() {
  assert get(policy(), "https://localhost:1/x")
    == Error(Failure(NotSent, transport.ConnectionRefused))
}

pub fn destination_policy_test() {
  let resolver = fn(addresses) { Some(fn(_host, _timeout) { Ok(addresses) }) }
  let p = fn(addresses) {
    transport.Policy(
      ..policy(),
      allow_loopback: False,
      resolver: resolver(addresses),
    )
  }
  assert get(p([Ipv4(10, 0, 0, 7)]), "https://idp.example/x")
    == Error(Failure(NotSent, transport.DestinationRejected))
  assert get(
      p([Ipv4(93, 184, 216, 34), Ipv4(169, 254, 169, 254)]),
      "https://idp.example/x",
    )
    == Error(Failure(NotSent, transport.DestinationRejected))
  assert get(
      transport.Policy(..policy(), allowed_hosts: Some(["idp.example"])),
      "https://evil.example/x",
    )
    == Error(Failure(NotSent, transport.DestinationRejected))
  assert get(
      transport.Policy(..policy(), resolver: Some(fn(_, _) { Ok([]) })),
      "https://idp.example/x",
    )
    == Error(Failure(NotSent, transport.ResolutionFailed))
}

/// The destination is resolved once; the connection uses that answer.
pub fn resolution_happens_once_test() {
  use s <- with_server("localhost", support.OkJson)
  let counter = support.clock_new(0)
  let resolver = fn(_host, _timeout) {
    let n = support.clock_read(counter) + 1
    support.clock_set(counter, n)
    case n {
      1 -> Ok([Ipv4(127, 0, 0, 1)])
      _ -> Ok([Ipv4(10, 0, 0, 1)])
    }
  }
  let assert Ok(_) =
    get(
      transport.Policy(..policy(), resolver: Some(resolver)),
      support.server_url(s, "/x"),
    )
  assert support.clock_read(counter) == 1
}

pub fn classify_address_test() {
  let cases = [
    #(Ipv4(8, 8, 8, 8), transport.Public),
    #(Ipv4(127, 0, 0, 1), transport.Loopback),
    #(Ipv4(10, 1, 2, 3), transport.Private),
    #(Ipv4(172, 16, 0, 1), transport.Private),
    #(Ipv4(172, 32, 0, 1), transport.Public),
    #(Ipv4(192, 168, 1, 1), transport.Private),
    #(Ipv4(169, 254, 169, 254), transport.Reserved),
    #(Ipv4(100, 64, 0, 1), transport.Private),
    #(Ipv4(0, 0, 0, 0), transport.Reserved),
    #(Ipv4(224, 0, 0, 1), transport.Reserved),
    #(Ipv4(255, 255, 255, 255), transport.Reserved),
    #(Ipv6(0, 0, 0, 0, 0, 0, 0, 1), transport.Loopback),
    #(Ipv6(0, 0, 0, 0, 0, 0xFFFF, 0xA9FE, 0xA9FE), transport.Reserved),
    #(Ipv6(0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 1), transport.Loopback),
    #(Ipv6(0xFD00, 0, 0, 0, 0, 0, 0, 1), transport.Private),
    #(Ipv6(0xFE80, 0, 0, 0, 0, 0, 0, 1), transport.Reserved),
    #(Ipv6(0x2606, 0x4700, 0, 0, 0, 0, 0, 1), transport.Public),
    #(Ipv6(0x64, 0xFF9B, 0, 0, 0, 0, 0x0A00, 1), transport.Private),
  ]
  list.each(cases, fn(c) {
    assert #(c.0, transport.classify(c.0)) == #(c.0, c.1)
  })
}

// --- oidcc adapter -------------------------------------------------------------

@external(erlang, "warden_test_support_ffi", "adapter_request")
fn adapter_request(adapter: a, url: String) -> decode.Dynamic

pub fn oidcc_adapter_reduces_error_bodies_test() {
  let adapter = oidcc_transport.adapter(policy())
  {
    use s <- with_server("localhost", support.ErrorBody)
    let assert Ok(#(400, body)) =
      decode.run(
        adapter_request(adapter, support.server_url(s, "/x")),
        status_body(),
      )
    let assert Ok(text) = bit_array.to_string(body)
    assert json.parse(text, decode.at(["error"], decode.string))
      == Ok("invalid_grant")
    assert text == "{\"error\":\"invalid_grant\"}"
  }
  {
    use s <- with_server("localhost", support.HtmlError)
    assert decode.run(
        adapter_request(adapter, support.server_url(s, "/x")),
        status_body(),
      )
      == Ok(#(500, <<>>))
  }
  use s <- with_server("localhost", support.BadJson)
  assert decode.run(
      adapter_request(adapter, support.server_url(s, "/x")),
      decode.string,
    )
    == Ok("sent:malformed_response")
}

fn status_body() -> decode.Decoder(#(Int, BitArray)) {
  use status <- decode.field(0, decode.int)
  use body <- decode.field(1, decode.bit_array)
  decode.success(#(status, body))
}
