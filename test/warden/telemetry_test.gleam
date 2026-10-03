//// Warden's typed events, received through sinal: closed values only, and
//// the caller's correlation on every event and HTTP Gun request.

import gleam/erlang/process
import gleam/http/request
import gleam/list
import gleam/option.{None, Some}
import http_gun/telemetry as http_telemetry
import sinal
import sinal/correlation
import sinal/fields
import warden
import warden/internal/transport
import warden/telemetry
import warden/testing
import warden_test_support as support

fn drain(inbox, acc) {
  case process.receive(inbox, 0) {
    Ok(item) -> drain(inbox, [item, ..acc])
    Error(Nil) -> list.reverse(acc)
  }
}

fn observed(run: fn() -> a) -> #(a, List(telemetry.HttpRequest)) {
  let inbox = process.new_subject()
  let plan =
    sinal.subscriptions([
      sinal.subscription(telemetry.http_request(), fn(measurements, request) {
        assert measurements.duration_ms >= 0
        process.send(inbox, request)
      }),
    ])
  let assert Ok(sinal.SubscriptionCompletion(work_result:, cleanup_failures: [])) =
    sinal.with_subscriptions(plan, run)
  #(work_result, drain(inbox, []))
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
  assert event.method == telemetry.Get
  assert event.host == "localhost"
  assert event.outcome == telemetry.Status(200)
  assert event.correlation == None
}

pub fn failure_event_carries_send_evidence_test() {
  let policy = transport.policy(transport.SystemTrust)
  let #(_, events) =
    observed(fn() { send(policy, "https://localhost:1/refused-observed") })
  let assert [event] =
    list.filter(events, fn(e) { e.path == "/refused-observed" })
  assert event.outcome
    == telemetry.Failed(
      evidence: telemetry.NotSent,
      reason: telemetry.DestinationRejected,
    )
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

/// R10: a correlation set with `with_correlation` reaches Warden's own HTTP
/// events, HTTP Gun's events for the same requests, and the login, refresh
/// and logout events, so one request can be followed without pid joins.
pub fn correlation_follows_the_session_test() {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  let assert Ok(client) =
    warden.new(testing.config(provider, "https://app.test/callback"))
  let assert Ok(Nil) = warden.start(client)
  let correlation = correlation.from_key("request-42")
  let tagged = warden.with_correlation(client, correlation)
  let http = process.new_subject()
  let gun = process.new_subject()
  let sessions = process.new_subject()
  let plan =
    sinal.subscriptions([
      sinal.subscription(telemetry.http_request(), fn(_, request) {
        process.send(http, #(request.path, request.correlation))
      }),
      sinal.subscription(http_telemetry.event(), fn(_, metadata) {
        process.send(gun, metadata.correlation)
      }),
      sinal.subscription(telemetry.login(), fn(_, login) {
        process.send(sessions, #("login", login.correlation))
      }),
      sinal.subscription(telemetry.refresh(), fn(_, refresh) {
        assert refresh.outcome == telemetry.Refreshed
        process.send(sessions, #("refresh", refresh.correlation))
      }),
      sinal.subscription(telemetry.logout(), fn(_, logout) {
        assert logout.revocation == telemetry.Revoked
        process.send(sessions, #("logout", logout.correlation))
      }),
    ])
  let assert Ok(_) =
    sinal.with_subscriptions(plan, fn() {
      let assert Ok(redirect) =
        warden.begin_login(tagged, request.new(), warden.default_login())
      let assert Ok(callback) =
        testing.authorize(provider, redirect, subject: "ada")
      let assert Ok(session) = warden.complete_login(tagged, callback)
      let assert Ok(access) = warden.refresh(tagged, session)
      let assert Ok(_) =
        warden.logout(tagged, access.session, warden.default_logout())
      Nil
    })
  let http_events = drain(http, [])
  assert list.map(http_events, fn(e) { e.0 }) == ["/token", "/token", "/revoke"]
  assert list.all(http_events, fn(e) { e.1 == Some(correlation) })
  let gun_events = drain(gun, [])
  assert gun_events != []
  assert list.all(gun_events, fn(c) { c == Some(correlation) })
  assert drain(sessions, [])
    == [
      #("login", Some(correlation)),
      #("refresh", Some(correlation)),
      #("logout", Some(correlation)),
    ]
  warden.stop(client)
  testing.stop_provider(provider)
}

/// Every closed value round-trips through its codec, so a constructor
/// missing from a `values` list is caught here.
pub fn every_outcome_round_trips_test() {
  let event = telemetry.http_request()
  list.each(telemetry.transport_reasons, fn(reason) {
    let metadata =
      telemetry.HttpRequest(
        method: telemetry.Post,
        host: "h",
        path: "/p",
        outcome: telemetry.Failed(telemetry.MaybeSent, reason),
        correlation: None,
      )
    let codec = sinal.metadata_fields(event)
    assert fields.decode(codec, fields.encode(codec, metadata)) == Ok(metadata)
  })
  list.each(telemetry.login_outcomes, fn(outcome) {
    let codec = sinal.metadata_fields(telemetry.login())
    let value = telemetry.Login(outcome:, correlation: None)
    let assert Ok(Nil) = fields.check(codec, value)
    assert fields.decode(codec, fields.encode(codec, value)) == Ok(value)
  })
  list.each(telemetry.refresh_outcomes, fn(outcome) {
    let codec = sinal.metadata_fields(telemetry.refresh())
    let value = telemetry.Refresh(outcome:, correlation: None)
    let assert Ok(Nil) = fields.check(codec, value)
    assert fields.decode(codec, fields.encode(codec, value)) == Ok(value)
  })
  list.each(telemetry.revocations, fn(revocation) {
    let codec = sinal.metadata_fields(telemetry.logout())
    let value = telemetry.Logout(revocation:, correlation: None)
    let assert Ok(Nil) = fields.check(codec, value)
    assert fields.decode(codec, fields.encode(codec, value)) == Ok(value)
  })
}
