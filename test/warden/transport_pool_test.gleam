//// The supervised shared HTTP Gun client behind `transport.send`: reuse,
//// replacement after a peer close, restart, caller death, deadlines and
//// mailbox hygiene.

import gleam/dynamic.{type Dynamic}
import gleam/erlang/process.{type Pid}
import gleam/int
import gleam/option.{None, Some}
import gleam/otp/actor
import gleam/otp/static_supervisor as supervisor
import gleam/string
import warden
import warden/internal/transport.{Failure, NotSent, Sent}
import warden_login_test
import warden_test_support as support

type Server

@external(erlang, "warden_transport_probe_ffi", "capture_server")
fn capture_server(address: Dynamic, port: Int, cert: String) -> #(Int, Server)

@external(erlang, "warden_transport_probe_ffi", "silent_server")
fn silent_server(cert: String, unused: Nil) -> #(Int, Server)

@external(erlang, "warden_transport_probe_ffi", "connections")
fn connections(server: Server) -> Int

@external(erlang, "warden_transport_probe_ffi", "close_connections")
fn close_connections(server: Server) -> Nil

@external(erlang, "warden_transport_probe_ffi", "stop")
fn stop(server: Server) -> Nil

@external(erlang, "warden_transport_probe_ffi", "mailbox_size")
fn mailbox_size() -> Int

@external(erlang, "warden_transport_probe_ffi", "kill_children")
fn kill_children(supervisor: Pid) -> Nil

@external(erlang, "gleam_stdlib", "identity")
fn to_dynamic(value: a) -> Dynamic

fn policy() -> transport.Policy {
  transport.Policy(
    ..transport.policy(transport.Anchors([support.ca_der()])),
    allow_loopback: True,
    timeout_ms: 2000,
    max_body: 4096,
  )
}

/// Run `body` with a policy bound to a supervised pool; returns the
/// supervisor pid for restart tests.
fn with_pool(body: fn(transport.Policy, Pid) -> a) -> a {
  let pool = transport.new_pool()
  let assert Ok(actor.Started(pid: sup, ..)) =
    supervisor.new(supervisor.OneForOne)
    |> supervisor.add(transport.pool_child(policy(), pool))
    |> supervisor.start
  let result = body(transport.Policy(..policy(), pool: Some(pool)), sup)
  process.unlink(sup)
  process.kill(sup)
  result
}

fn get(policy: transport.Policy, url: String) {
  transport.send(policy, transport.Request(transport.Get, url, [], None))
}

fn local_server() -> #(String, Server) {
  let #(port, server) =
    capture_server(to_dynamic(#(127, 0, 0, 1)), 0, "localhost")
  #("https://localhost:" <> int.to_string(port) <> "/x", server)
}

pub fn pooled_requests_reuse_one_connection_test() {
  use pooled, _ <- with_pool
  let #(url, server) = local_server()
  let assert Ok(_) = get(pooled, url)
  let assert Ok(_) = get(pooled, url)
  assert connections(server) == 1
  stop(server)
}

/// A request soon after the provider closes an idle connection uses a new
/// connection instead of failing as "may have been sent", which would lose a
/// single-use code exchange.
pub fn a_peer_closed_connection_is_not_reused_test() {
  use pooled, _ <- with_pool
  let #(url, server) = local_server()
  let assert Ok(_) = get(pooled, url)
  close_connections(server)
  process.sleep(100)
  let assert Ok(response) = get(pooled, url)
  assert response.status == 200
  assert connections(server) == 2
  stop(server)
}

/// A supervisor restart starts a new HTTP Gun client; requests find it.
pub fn the_pool_survives_a_restart_test() {
  use pooled, sup <- with_pool
  let #(url, server) = local_server()
  let assert Ok(_) = get(pooled, url)
  kill_children(sup)
  process.sleep(100)
  let assert Ok(response) = get(pooled, url)
  assert response.status == 200
  stop(server)
}

pub fn a_released_pool_refuses_before_sending_test() {
  let pool = transport.new_pool()
  let #(url, server) = local_server()
  assert get(transport.Policy(..policy(), pool: Some(pool)), url)
    == Error(Failure(NotSent, transport.InternalError))
  assert connections(server) == 0
  stop(server)
}

pub fn a_caller_that_dies_leaves_the_pool_serving_test() {
  use pooled, _ <- with_pool
  let slow = support.server_start("localhost", support.Slow)
  let caller =
    process.spawn_unlinked(fn() { get(pooled, support.server_url(slow, "/x")) })
  process.sleep(200)
  process.kill(caller)
  let #(url, server) = local_server()
  let assert Ok(response) = get(pooled, url)
  assert response.status == 200
  support.server_stop(slow)
  stop(server)
}

pub fn a_peer_that_never_reads_ends_at_the_deadline_test() {
  use pooled, _ <- with_pool
  let #(port, server) = silent_server("localhost", Nil)
  let started = transport.monotonic_ms()
  let result =
    transport.send(
      transport.Policy(..pooled, timeout_ms: 500),
      transport.Request(
        transport.Post,
        "https://localhost:" <> int.to_string(port) <> "/x",
        [],
        Some(<<string.repeat("a", transport.max_request_body):utf8>>),
      ),
    )
  assert result == Error(Failure(Sent, transport.Timeout))
  assert transport.monotonic_ms() - started < 1500
  stop(server)
}

/// No late HTTP Gun message reaches a long-lived caller after a timeout.
pub fn a_timed_out_request_leaves_the_caller_mailbox_clean_test() {
  use pooled, _ <- with_pool
  let slow = support.server_start("localhost", support.Slow)
  let before = mailbox_size()
  assert get(
      transport.Policy(..pooled, timeout_ms: 300),
      support.server_url(slow, "/x"),
    )
    == Error(Failure(Sent, transport.Timeout))
  // Past the server's 3 s reply.
  process.sleep(3200)
  assert mailbox_size() == before
  support.server_stop(slow)
}

/// Metadata services stay unreachable even where private networks are.
pub fn metadata_addresses_are_refused_with_private_permission_test() {
  let refused = fn(address) {
    get(
      transport.Policy(
        ..policy(),
        allow_private: True,
        resolver: Some(fn(_, _) { Ok([address]) }),
      ),
      "https://idp.example/x",
    )
  }
  assert refused(transport.Ipv4(100, 100, 100, 200))
    == Error(Failure(NotSent, transport.DestinationRejected))
  assert refused(transport.Ipv6(0xFD00, 0xEC2, 0, 0, 0, 0, 0, 0x254))
    == Error(Failure(NotSent, transport.DestinationRejected))
}

/// A Warden client sends through its supervised pool, and stopping the
/// client releases it.
pub fn a_warden_client_owns_and_releases_its_pool_test() {
  let provider = support.provider_start(support.Standard)
  let client = warden_login_test.start(warden_login_test.settings(provider))
  let http = client.http
  let assert Some(_) = http.pool
  let assert Ok(response) =
    get(
      http,
      support.provider_issuer(provider) <> "/.well-known/openid-configuration",
    )
  assert response.status == 200
  warden.stop(client)
  assert get(http, support.provider_issuer(provider) <> "/jwks")
    == Error(Failure(NotSent, transport.InternalError))
  support.provider_stop(provider)
}
