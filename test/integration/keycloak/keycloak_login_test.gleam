//// MVP acceptance: real logins through Warden's public API against the
//// pinned Keycloak (`scripts/keycloak up`), over verified TLS with an
//// explicit test trust anchor.

import gleam/http/request
import gleam/list
import gleam/option.{Some}
import gleam/string
import gleam/time/duration
import gleam/uri
import warden
import warden/config
import warden/testing
import warden_test_support as support

const issuer = "https://localhost:18443/realms/warden"

fn settings() -> config.Config {
  config.new(
    issuer:,
    client_id: "warden-rp",
    redirect_uri: "https://localhost:1/callback",
    authentication: config.ClientSecretBasic(config.secret(
      "warden-rp-disposable-secret",
    )),
  )
  |> config.with_scopes(["profile", "email"])
  |> config.with_trust(config.TrustAnchorsPem(support.ca_pem()))
  |> config.with_destinations(config.AllowLoopbackForTesting)
}

fn start(config: config.Config) -> warden.Client {
  support.start_client(config)
}

fn login(
  client: warden.Client,
  user: String,
) -> #(String, warden.LoginRedirect) {
  let assert Ok(redirect) =
    warden.begin_login(client, request.new(), warden.default_login())
  let assert Ok(support.Query(query)) =
    support.keycloak_login(
      warden.login_url(redirect),
      user,
      user <> "-disposable",
    )
  #(query, redirect)
}

fn param(query: String, name: String) -> String {
  let assert Ok(params) = uri.parse_query(query)
  let assert Ok(value) = list.key_find(params, name)
  value
}

fn replace_param(query: String, name: String, value: String) -> String {
  let assert Ok(params) = uri.parse_query(query)
  params
  |> list.map(fn(p) {
    case p.0 == name {
      True -> #(name, value)
      False -> p
    }
  })
  |> uri.query_to_string
}

pub fn login_verifies_identity_and_confirms_custody_test() {
  let client = start(settings())
  let #(query, binding) = login(client, "alice")
  let assert Ok(session) =
    warden.complete_login(client, support.query_callback(binding, query))
  let identity = warden.session_identity(session)
  assert warden.issuer(identity) == issuer
  assert warden.subject(identity) != ""
  assert warden.email(identity) == Some("alice@example.test")
  assert warden.email_verified(identity) == Some(True)
  assert warden.identity_key(identity)
    == warden.IdentityKey(issuer:, subject: warden.subject(identity))
  // The session is restorable from its custody reference.
  let assert Ok(restored) =
    warden.restore_session(client, warden.session_reference(session))
  assert warden.subject(warden.session_identity(restored))
    == warden.subject(identity)
  let assert Ok(warden.Access(token:, ..)) =
    warden.access_token(client, session)
  assert warden.access_token_value(token) != ""
  // No token value is visible through generic inspection.
  assert !string.contains(
    string.inspect(token),
    warden.access_token_value(token),
  )
  warden.stop(client)
}

pub fn replayed_callback_is_rejected_test() {
  let client = start(settings())
  let #(query, binding) = login(client, "alice")
  let assert Ok(_) =
    warden.complete_login(client, support.query_callback(binding, query))
  let assert Error(warden.LoginReplayed) =
    warden.complete_login(client, support.query_callback(binding, query))
  warden.stop(client)
}

pub fn invalid_binding_or_issuer_does_not_consume_the_login_test() {
  let client = start(settings())
  let #(query, binding) = login(client, "alice")
  let assert Ok(other) =
    warden.begin_login(client, request.new(), warden.default_login())
  // Another browser's binding.
  let assert Error(warden.CallbackRejected(warden.BrowserBindingMismatch)) =
    warden.complete_login(client, support.query_callback(other, query))
  // No binding cookie.
  let assert Error(warden.CallbackRejected(warden.BrowserBindingMissing)) =
    warden.complete_login(
      client,
      support.without_binding(support.query_callback(binding, query)),
    )
  // Mix-up: a different issuer in the response.
  let assert Error(warden.CallbackRejected(warden.CallbackIssuerMismatch)) =
    warden.complete_login(
      client,
      support.query_callback(
        binding,
        replace_param(query, "iss", "https://evil.example"),
      ),
    )
  // Keycloak advertises RFC 9207 support, so a missing iss is rejected.
  let without_iss =
    uri.parse_query(query)
    |> fn(r) {
      let assert Ok(p) = r
      p
    }
    |> list.filter(fn(p) { p.0 != "iss" })
    |> uri.query_to_string
  let assert Error(warden.CallbackRejected(warden.CallbackIssuerMissing)) =
    warden.complete_login(client, support.query_callback(binding, without_iss))
  // A forged state finds no login.
  let assert Error(warden.CallbackRejected(warden.UnknownState)) =
    warden.complete_login(
      client,
      support.query_callback(binding, replace_param(query, "state", "forged")),
    )
  // The legitimate callback still completes.
  let assert Ok(_) =
    warden.complete_login(client, support.query_callback(binding, query))
  warden.stop(client)
}

pub fn malformed_callbacks_are_rejected_before_lookup_test() {
  let client = start(settings())
  let #(query, binding) = login(client, "alice")
  let code = param(query, "code")
  let cases = [
    #(query <> "&code=" <> code, warden.DuplicateCallbackParameter),
    #(query <> "&error=access_denied", warden.AmbiguousCallback),
    #(replace_param(query, "code", ""), warden.EmptyCode),
    #("state=" <> param(query, "state"), warden.MissingCode),
    #("code=abc", warden.MissingState),
    #("state=%zz&code=1", warden.CallbackEncodingInvalid),
    #(string.repeat("a", 20_000), warden.CallbackTooLarge),
  ]
  list.each(cases, fn(c) {
    let assert Error(warden.CallbackMalformed(problem)) =
      warden.complete_login(client, support.query_callback(binding, c.0))
    assert problem == c.1
  })
  // A form-post body is refused while query mode is configured.
  let assert Error(warden.CallbackMalformed(warden.UnexpectedResponseMode)) =
    warden.complete_login(client, support.form_callback(binding, query))
  let assert Ok(_) =
    warden.complete_login(client, support.query_callback(binding, query))
  warden.stop(client)
}

/// Two concurrent callbacks for one login: exactly one token request and one
/// session; the other callback observes replay.
pub fn concurrent_callbacks_send_one_token_request_test() {
  let client = start(settings())
  let #(query, binding) = login(client, "alice")
  support.count_reset()
  let attempt = fn() {
    warden.complete_login(client, support.query_callback(binding, query))
  }
  let results = support.spawn_collect(list.repeat(attempt, 8), 30_000)
  let completed =
    list.count(results, fn(r) {
      case r {
        Ok(_) -> True
        _ -> False
      }
    })
  let replayed = list.count(results, fn(r) { r == Error(warden.LoginReplayed) })
  assert completed == 1
  assert replayed == 7
  assert support.count("/protocol/openid-connect/token") == 1
  warden.stop(client)
}

pub fn form_post_login_test() {
  let client = start(settings() |> config.with_response_mode(config.FormPost))
  let assert Ok(redirect) =
    warden.begin_login(client, request.new(), warden.default_login())
  assert string.contains(warden.login_url(redirect), "response_mode=form_post")
  let assert Ok(support.FormPost(body)) =
    support.keycloak_login(
      warden.login_url(redirect),
      "alice",
      "alice-disposable",
    )
  let assert Error(warden.CallbackMalformed(warden.UnexpectedResponseMode)) =
    warden.complete_login(client, support.query_callback(redirect, body))
  let assert Ok(session) =
    warden.complete_login(client, support.form_callback(redirect, body))
  assert warden.email(warden.session_identity(session))
    == Some("alice@example.test")
  warden.stop(client)
}

pub fn provider_denial_consumes_without_exchange_test() {
  let client = start(settings())
  let options =
    warden.LoginOptions(..warden.default_login(), prompt: [warden.PromptNone])
  let assert Ok(redirect) = warden.begin_login(client, request.new(), options)
  let assert Ok(support.Query(query)) =
    support.visit(warden.login_url(redirect))
  support.count_reset()
  let assert Error(warden.ProviderDenied(warden.LoginRequired)) =
    warden.complete_login(client, support.query_callback(redirect, query))
  assert support.count("/protocol/openid-connect/token") == 0
  let assert Error(warden.LoginReplayed) =
    warden.complete_login(client, support.query_callback(redirect, query))
  warden.stop(client)
}

pub fn concurrent_tabs_share_a_binding_test() {
  let client = start(settings())
  let assert Ok(first) =
    warden.begin_login(client, request.new(), warden.default_login())
  let binding = first
  let assert Ok(second) =
    warden.begin_login(
      client,
      testing.browser_request(first),
      warden.default_login(),
    )
  assert testing.browser_request(second).headers
    == testing.browser_request(first).headers
  assert warden.login_url(first) != warden.login_url(second)
  let assert Ok(support.Query(q1)) =
    support.keycloak_login(warden.login_url(first), "alice", "alice-disposable")
  let assert Ok(support.Query(q2)) =
    support.keycloak_login(warden.login_url(second), "bob", "bob-disposable")
  // Complete in reverse order.
  let assert Ok(s2) =
    warden.complete_login(client, support.query_callback(binding, q2))
  let assert Ok(s1) =
    warden.complete_login(client, support.query_callback(binding, q1))
  assert warden.email(warden.session_identity(s1)) == Some("alice@example.test")
  assert warden.email(warden.session_identity(s2)) == Some("bob@example.test")
  warden.stop(client)
}

pub fn expired_login_is_rejected_test() {
  let client =
    start(settings() |> config.with_login_lifetime(duration.seconds(1)))
  let #(query, binding) = login(client, "alice")
  let _ = support.sleep(1100)
  support.count_reset()
  let assert Error(warden.LoginExpired) =
    warden.complete_login(client, support.query_callback(binding, query))
  assert support.count("/protocol/openid-connect/token") == 0
  warden.stop(client)
}

/// RFC 9700 §4.5 code injection: an attacker's authorization code presented
/// with the victim's own state, binding and issuer. Warden sends the victim
/// transaction's PKCE verifier, which does not match the attacker's
/// challenge, so the provider rejects the exchange.
pub fn injected_code_is_rejected_by_pkce_test() {
  let client = start(settings())
  let #(attacker_query, _) = login(client, "bob")
  let assert Ok(victim) =
    warden.begin_login(client, request.new(), warden.default_login())
  let assert Ok(#(_, victim_query)) =
    string.split_once(warden.login_url(victim), "?")
  let injected =
    uri.query_to_string([
      #("code", param(attacker_query, "code")),
      #("state", param(victim_query, "state")),
      #("iss", issuer),
    ])
  let assert Error(warden.ExchangeRejected(warden.InvalidGrant)) =
    warden.complete_login(client, support.query_callback(victim, injected))
  warden.stop(client)
}
