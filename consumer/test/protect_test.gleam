//// The reference app's browser-facing protections.

import gleam/http
import gleam/http/cookie
import gleam/list
import gleam/option.{Some}
import warden_reference/protect
import wisp
import wisp/simulate

const origin = "https://app.example"

pub fn session_cookie_uses_the_host_prefix_and_is_always_secure_test() {
  // __Host- prevents sibling subdomains from planting the cookie.
  assert protect.session_cookie == "__Host-warden_session"
  // Secure does not depend on the request scheme, which is plain HTTP
  // behind a TLS-terminating proxy.
  let attributes = protect.session_attributes(600)
  assert attributes.secure
  assert attributes.http_only
  assert attributes.path == Some("/")
  assert attributes.domain == option.None
  assert attributes.same_site == Some(cookie.Lax)
}

pub fn state_changing_requests_must_be_same_origin_test() {
  let post = simulate.request(http.Post, "/logout")
  // A cross-site form post.
  assert !protect.same_origin(
    simulate.header(post, "origin", "https://evil.example"),
    origin,
  )
  assert !protect.same_origin(
    simulate.header(post, "sec-fetch-site", "cross-site"),
    origin,
  )
  // No browser provenance at all fails closed.
  assert !protect.same_origin(post, origin)
  assert protect.same_origin(simulate.header(post, "origin", origin), origin)
  assert protect.same_origin(
    simulate.header(post, "sec-fetch-site", "same-origin"),
    origin,
  )
}

pub fn sessions_expire_on_the_server_test() {
  // The signed cookie carries its issue time; the browser's Max-Age is not
  // the only limit.
  let value = protect.session_value("reference-1", issued_at: 1000)
  assert protect.read_session_value(value, now: 1000 + 3600, max_age: 3600)
    == Ok("reference-1")
  assert protect.read_session_value(value, now: 1001 + 3600, max_age: 3600)
    == Error(Nil)
  assert protect.read_session_value("reference-1", now: 1000, max_age: 3600)
    == Error(Nil)
}

pub fn opaque_session_references_keep_their_periods_test() {
  let reference = "synthetic.epoch.synthetic-reference"
  let value = protect.session_value(reference, issued_at: 1000)
  assert value == reference <> ".1000"
  assert protect.read_session_value(value, now: 1000, max_age: 3600)
    == Ok(reference)
  assert protect.read_session_value(value, now: 4600, max_age: 3600)
    == Ok(reference)
  assert protect.read_session_value(value, now: 4601, max_age: 3600)
    == Error(Nil)
}

pub fn malformed_and_future_session_timestamps_are_refused_test() {
  assert protect.read_session_value(
      "synthetic.reference",
      now: 1000,
      max_age: 3600,
    )
    == Error(Nil)
  assert protect.read_session_value(
      "synthetic.reference.invalid",
      now: 1000,
      max_age: 3600,
    )
    == Error(Nil)
  assert protect.read_session_value(
      "synthetic.reference.",
      now: 1000,
      max_age: 3600,
    )
    == Error(Nil)
  let future = protect.session_value("synthetic.reference", issued_at: 1001)
  assert protect.read_session_value(future, now: 1000, max_age: 3600)
    == Error(Nil)
}

pub fn responses_carry_security_headers_test() {
  let response = protect.security_headers(wisp.ok())
  let header = fn(name) { list.key_find(response.headers, name) }
  assert header("cache-control") == Ok("no-store")
  assert header("referrer-policy") == Ok("no-referrer")
  assert header("x-content-type-options") == Ok("nosniff")
  assert header("content-security-policy")
    == Ok("default-src 'none'; frame-ancestors 'none'")
  assert header("strict-transport-security")
    == Ok("max-age=31536000; includeSubDomains")
}
