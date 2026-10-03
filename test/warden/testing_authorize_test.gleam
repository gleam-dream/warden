//// The test provider's HTTP login page (`/authorize`), per-login redirect
//// URIs, access-token revocation and audiences set after start.

import gleam/http
import gleam/http/request.{type Request}
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleam/uri
import warden
import warden/config
import warden/resource
import warden/testing

type Method {
  Get
  Post
}

type HttpResponse =
  #(Int, List(#(String, String)), String)

@external(erlang, "warden_testing_http_ffi", "request")
fn https(
  method: Method,
  url: String,
  body: String,
  ca_pem: String,
) -> Result(HttpResponse, Nil)

const callback_url = "https://app.test/callback"

fn started(
  options: testing.ProviderOptions,
  configure: fn(config.Config) -> config.Config,
) -> #(testing.Provider, warden.Client) {
  let assert Ok(provider) = testing.start_provider(options)
  let assert Ok(client) =
    warden.new(configure(testing.config(provider, callback_url)))
  let assert Ok(Nil) = warden.start(client)
  #(provider, client)
}

fn stop(provider: testing.Provider, client: warden.Client) -> Nil {
  warden.stop(client)
  testing.stop_provider(provider)
}

fn header(response: HttpResponse, name: String) -> Result(String, Nil) {
  list.key_find(response.1, name)
}

/// Follow `login_url` over HTTPS as a browser would, and turn the
/// provider's redirect into the callback request the app receives.
fn follow(
  provider: testing.Provider,
  redirect: warden.LoginRedirect,
) -> #(HttpResponse, Request(String)) {
  let assert Ok(answer) =
    https(
      Get,
      warden.login_url(redirect),
      "",
      testing.trust_anchor_pem(provider),
    )
  let assert Ok(location) = header(answer, "location")
  let assert Ok(target) = uri.parse(location)
  let assert Ok(callback) = request.from_uri(target)
  let cookie =
    testing.browser_request(redirect)
    |> request.get_header("cookie")
  let callback = case cookie {
    Ok(cookie) -> request.set_header(callback, "cookie", cookie)
    Error(Nil) -> callback
  }
  #(answer, request.set_body(callback, ""))
}

fn query(location: String) -> List(#(String, String)) {
  let assert Ok(#(_, query)) = string.split_once(location, "?")
  let assert Ok(params) = uri.parse_query(query)
  params
}

pub fn http_login_signs_in_the_configured_user_test() {
  let #(provider, client) =
    started(
      testing.provider_options() |> testing.with_login(testing.SignIn("ada")),
      fn(c) { c },
    )
  let assert Ok(redirect) =
    warden.begin_login(client, request.new(), warden.default_login())
  let #(answer, callback) = follow(provider, redirect)
  assert answer.0 == 303
  assert header(answer, "cache-control") == Ok("no-store")
  let assert Ok(location) = header(answer, "location")
  assert string.starts_with(location, callback_url <> "?")
  let params = query(location)
  assert list.key_find(params, "iss") == Ok(testing.issuer(provider))
  assert list.key_find(params, "code") |> option.from_result != None
  let assert Ok(session) = warden.complete_login(client, callback)
  assert warden.subject(warden.session_identity(session)) == "ada"
  assert testing.requests(provider).authorizations == 1
  assert testing.requests(provider).code_grants == 1
  stop(provider, client)
}

pub fn default_user_login_hint_and_set_login_test() {
  let #(provider, client) = started(testing.provider_options(), fn(c) { c })
  let login = fn(options) {
    let assert Ok(redirect) = warden.begin_login(client, request.new(), options)
    warden.complete_login(client, follow(provider, redirect).1)
  }
  let assert Ok(session) = login(warden.default_login())
  assert warden.subject(warden.session_identity(session)) == "test-user"
  // The request's login_hint picks the user per login.
  let assert Ok(session) =
    login(
      warden.LoginOptions(..warden.default_login(), login_hint: Some("bob")),
    )
  assert warden.subject(warden.session_identity(session)) == "bob"
  // A scripted decision changes the next logins.
  testing.set_login(provider, testing.SignIn("carol"))
  let assert Ok(session) = login(warden.default_login())
  assert warden.subject(warden.session_identity(session)) == "carol"
  testing.set_login(provider, testing.Refuse("access_denied"))
  assert login(warden.default_login())
    == Error(warden.ProviderDenied(warden.AccessDenied))
  testing.set_login(provider, testing.Refuse("login_required"))
  assert login(warden.default_login())
    == Error(warden.ProviderDenied(warden.LoginRequired))
  assert testing.requests(provider).authorizations == 5
  assert testing.requests(provider).code_grants == 3
  stop(provider, client)
}

pub fn http_login_with_form_post_test() {
  let #(provider, client) =
    started(testing.provider_options(), config.with_response_mode(
      _,
      config.FormPost,
    ))
  let assert Ok(redirect) =
    warden.begin_login(client, request.new(), warden.default_login())
  let assert Ok(page) =
    https(
      Get,
      warden.login_url(redirect),
      "",
      testing.trust_anchor_pem(provider),
    )
  assert page.0 == 200
  assert string.contains(page.2, "action=\"" <> callback_url <> "\"")
  // The scripted browser posts the form's hidden fields.
  let fields =
    string.split(page.2, "<input type=\"hidden\" name=\"")
    |> list.drop(1)
    |> list.map(fn(input) {
      let assert Ok(#(name, rest)) = string.split_once(input, "\" value=\"")
      let assert Ok(#(value, _)) = string.split_once(rest, "\">")
      #(name, value)
    })
  assert list.map(fields, fn(f) { f.0 }) == ["code", "state", "iss"]
  let assert Ok(cookie) =
    testing.browser_request(redirect) |> request.get_header("cookie")
  let assert Ok(callback) = request.to(callback_url)
  let callback =
    callback
    |> request.set_method(http.Post)
    |> request.set_header("content-type", "application/x-www-form-urlencoded")
    |> request.set_header("cookie", cookie)
    |> request.set_body(uri.query_to_string(fields))
  let assert Ok(session) = warden.complete_login(client, callback)
  assert warden.subject(warden.session_identity(session)) == "test-user"
  stop(provider, client)
}

pub fn authorize_never_redirects_to_an_unverified_client_test() {
  let #(provider, client) = started(testing.provider_options(), fn(c) { c })
  let assert Ok(redirect) =
    warden.begin_login(client, request.new(), warden.default_login())
  let url = warden.login_url(redirect)
  let ca = testing.trust_anchor_pem(provider)
  // Another client id: 400, no redirect.
  let other =
    string.replace(
      url,
      "client_id=" <> testing.client_id(provider),
      "client_id=x",
    )
  let assert Ok(refused) = https(Get, other, "", ca)
  assert refused.0 == 400
  assert header(refused, "location") == Error(Nil)
  // A redirect URI that is not absolute: 400, no redirect.
  let assert Ok(#(endpoint, _)) = string.split_once(url, "?")
  let assert Ok(no_uri) =
    https(
      Get,
      endpoint
        <> "?"
        <> uri.query_to_string([
        #("client_id", testing.client_id(provider)),
        #("redirect_uri", "/relative"),
        #("response_type", "code"),
      ]),
      "",
      ca,
    )
  assert no_uri.0 == 400
  // A verified client without PKCE: redirected back with invalid_request.
  let assert Ok(no_pkce) =
    https(
      Post,
      endpoint,
      uri.query_to_string([
        #("client_id", testing.client_id(provider)),
        #("redirect_uri", callback_url),
        #("response_type", "code"),
        #("state", "s1"),
      ]),
      ca,
    )
  assert no_pkce.0 == 303
  let assert Ok(location) = header(no_pkce, "location")
  let params = query(location)
  assert list.key_find(params, "error") == Ok("invalid_request")
  assert list.key_find(params, "state") == Ok("s1")
  assert list.key_find(params, "code") == Error(Nil)
  stop(provider, client)
}

/// A login may choose a redirect URI from the client's allowlist, matched
/// exactly; the code is exchanged with the same URI.
pub fn login_chooses_an_allowed_redirect_uri_test() {
  let second = "https://admin.app.test/callback"
  let #(provider, client) =
    started(
      testing.provider_options(),
      config.with_allowed_redirect_uris(_, [
        second,
      ]),
    )
  let choose = fn(uri) {
    warden.begin_login(
      client,
      request.new(),
      warden.LoginOptions(..warden.default_login(), redirect_uri: Some(uri)),
    )
  }
  let assert Ok(redirect) = choose(second)
  assert list.key_find(query(warden.login_url(redirect)), "redirect_uri")
    == Ok(second)
  let #(answer, callback) = follow(provider, redirect)
  let assert Ok(location) = header(answer, "location")
  assert string.starts_with(location, second <> "?")
  let assert Ok(_) = warden.complete_login(client, callback)
  // The configured URI may be named explicitly too.
  let assert Ok(redirect) = choose(callback_url)
  assert list.key_find(query(warden.login_url(redirect)), "redirect_uri")
    == Ok(callback_url)
  // Anything else fails closed: no prefix, case, port, slash or encoding
  // equivalence.
  let refused = Error(warden.InvalidLoginOption(warden.RedirectUriNotAllowed))
  list.each(
    [
      "https://admin.app.test/callback/",
      "https://admin.app.test/callback?next=/",
      "https://admin.app.test/callbac",
      "https://ADMIN.app.test/callback",
      "https://admin.app.test:443/callback",
      "https://admin.app.test/%63allback",
      "https://evil.test/callback",
      "",
    ],
    fn(uri) {
      assert choose(uri) == refused
    },
  )
  assert warden.login_error_action(warden.InvalidLoginOption(
      warden.RedirectUriNotAllowed,
    ))
    == warden.FixConfiguration
  assert warden.describe_login_error(warden.InvalidLoginOption(
      warden.RedirectUriNotAllowed,
    ))
    |> string.contains("redirect URI")
  stop(provider, client)
}

pub fn allowed_redirect_uris_are_validated_test() {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  assert testing.config(provider, callback_url)
    |> config.with_allowed_redirect_uris([
      "http://app.test/callback",
      "https://app.test/a#b",
      "https://app.test/ok",
    ])
    |> config.validate
    == Error([
      config.InvalidAllowedRedirectUri("http://app.test/callback"),
      config.InvalidAllowedRedirectUri("https://app.test/a#b"),
    ])
  assert testing.service_config(provider)
    |> config.with_allowed_redirect_uris(["https://app.test/ok"])
    |> config.validate
    == Error([config.AllowedRedirectUrisNeedLogin])
  assert config.describe_config_error(config.AllowedRedirectUrisNeedLogin)
    |> string.contains("with_allowed_redirect_uris")
  testing.stop_provider(provider)
}

/// A revoked access token is inactive at introspection at once; a local
/// JWT validator keeps accepting it until `exp` (RFC 9068 has no
/// revocation channel), which the test states rather than hides.
pub fn revoked_access_token_is_seen_by_introspection_only_test() {
  let #(provider, client) = started(testing.provider_options(), fn(c) { c })
  let token =
    testing.issue_access_token(
      provider,
      testing.access_token("ada")
        |> testing.with_audiences(["https://api.test"]),
    )
  let validator = resource.new(client, audience: "https://api.test")
  let assert Ok(warden.ActiveToken(_)) = warden.introspect(client, token)
  testing.revoke_access_token(provider, token)
  assert warden.introspect(client, token) == Ok(warden.InactiveToken)
  let assert Ok(claims) = resource.verify(validator, token)
  assert resource.subject(claims) == "ada"
  // Revoking an unknown token changes nothing.
  testing.revoke_access_token(provider, "unknown")
  stop(provider, client)
}

/// The audience of issued access tokens can be set after start, once the
/// application knows its own address.
pub fn access_token_audience_set_after_start_test() {
  let #(provider, client) = started(testing.provider_options(), fn(c) { c })
  let login = fn() {
    let assert Ok(redirect) =
      warden.begin_login(client, request.new(), warden.default_login())
    let assert Ok(session) =
      warden.complete_login(client, follow(provider, redirect).1)
    let assert Ok(access) = warden.access_token(client, session)
    warden.access_token_value(access.token)
  }
  let before = login()
  testing.set_access_token_audiences(provider, ["https://127.0.0.1:4100/mcp"])
  let after = login()
  let validator = resource.new(client, audience: "https://127.0.0.1:4100/mcp")
  assert resource.verify(validator, before) == Error(resource.AudienceMismatch)
  let assert Ok(claims) = resource.verify(validator, after)
  assert resource.audiences(claims) == ["https://127.0.0.1:4100/mcp"]
  let assert Ok(token) = warden.client_credentials(client, [])
  let assert Ok(claims) =
    resource.verify(validator, warden.access_token_value(token.access_token))
  assert resource.audiences(claims) == ["https://127.0.0.1:4100/mcp"]
  testing.set_access_token_audiences(provider, [])
  let assert Ok(token) = warden.client_credentials(client, [])
  let assert Ok(warden.ActiveToken(info)) =
    warden.introspect(client, warden.access_token_value(token.access_token))
  assert info.audiences == [testing.client_id(provider)]
  stop(provider, client)
}
