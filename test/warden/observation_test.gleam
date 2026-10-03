//// Warden's typed observation events, received through sinal.

import gleam/erlang/process
import gleam/list
import gleam/option.{None, Some}
import http_gun/telemetry as http_telemetry
import sinal
import warden/internal/transport
import warden/observation
import warden_test_support as support

fn observed(run: fn() -> a) -> #(a, List(observation.HttpRequest)) {
  let inbox = process.new_subject()
  let plan =
    sinal.subscriptions([
      sinal.subscription(observation.http_request(), fn(measurements, request) {
        assert measurements.duration_ms >= 0
        process.send(inbox, request)
      }),
    ])
  let assert Ok(sinal.SubscriptionCompletion(work_result:, cleanup_failures: [])) =
    sinal.with_subscriptions(plan, run)
  #(work_result, drain(inbox, []))
}

fn drain(inbox, acc) {
  case process.receive(inbox, 0) {
    Ok(request) -> drain(inbox, [request, ..acc])
    Error(Nil) -> list.reverse(acc)
  }
}

fn send(policy: transport.Policy, url: String) {
  transport.send(policy, transport.Request(transport.Get, url, [], None))
}

pub fn http_request_event_is_typed_and_closed_test() {
  let server = support.server_start("localhost", support.OkJson)
  let url = support.server_url(server, "/observed?code=secret-sentinel")
  let policy =
    transport.Policy(
      ..transport.policy(transport.Anchors([support.ca_der()])),
      allow_loopback: True,
    )
  let #(_, events) = observed(fn() { send(policy, url) })
  support.server_stop(server)
  let assert [event] = list.filter(events, fn(e) { e.path == "/observed" })
  assert event.method == observation.Get
  assert event.host == "localhost"
  assert event.outcome == observation.Status(200)
}

pub fn failure_event_carries_send_evidence_test() {
  let policy = transport.policy(transport.SystemTrust)
  let #(_, events) =
    observed(fn() { send(policy, "https://localhost:1/refused-observed") })
  let assert [event] =
    list.filter(events, fn(e) { e.path == "/refused-observed" })
  assert event.outcome
    == observation.Failed(sent: False, class: "destination_rejected")
}

pub fn http_gun_events_carry_the_warden_client_label_test() {
  let server = support.server_start("localhost", support.OkJson)
  let url = support.server_url(server, "/labelled")
  let policy =
    transport.Policy(
      ..transport.policy(transport.Anchors([support.ca_der()])),
      allow_loopback: True,
    )
  let inbox = process.new_subject()
  let plan =
    sinal.subscriptions([
      sinal.subscription(http_telemetry.event(), fn(_, metadata) {
        process.send(inbox, metadata.client)
      }),
    ])
  let assert Ok(sinal.SubscriptionCompletion(work_result: Ok(_), ..)) =
    sinal.with_subscriptions(plan, fn() { send(policy, url) })
  support.server_stop(server)
  let assert Ok(client) = process.receive(inbox, 1000)
  assert client == Some("warden")
  assert list.all(drain(inbox, []), fn(client) { client == Some("warden") })
}
