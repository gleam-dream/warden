//// An HTTP-level login through the reference app's real routes: the
//// browser follows `/login` to the test provider's `/authorize` over
//// HTTPS and comes back to `/callback`. The app has no test hook; the
//// provider's scripted login page signs the user in.

import gleam/crypto
import gleam/http
import gleam/http/request
import gleam/int
import gleam/list
import gleam/string
import warden
import warden/testing
import warden_reference/protect
import warden_reference/web
import wisp
import wisp/simulate

type Method {
  Get
}

@external(erlang, "warden_reference_http_ffi", "request")
fn https(
  method: Method,
  url: String,
  body: String,
  ca_pem: String,
) -> Result(#(Int, List(#(String, String)), String), Nil)

pub fn browser_signs_in_through_the_provider_login_page_test() {
  let #(provider, client, context, home_request) = sign_in()
  // Follow the application's signed cookie into an authenticated page.
  let home = web.handle(home_request, context)
  assert home.status == 200
  let assert wisp.Text(html) = home.body
  assert string.contains(html, "<dd id=\"subject\">ada</dd>")
  assert string.contains(html, "id=\"email\"")
  assert string.contains(html, "id=\"logout\"")
  assert !string.contains(html, "id=\"login\"")
  warden.stop(client)
  testing.stop_provider(provider)
}

pub fn modified_session_cookie_signatures_are_refused_test() {
  let #(provider, client, context, home_request) = sign_in()
  let assert Ok(signed) =
    request.get_cookies(home_request)
    |> list.key_find(protect.session_cookie)
  let modified =
    request.set_cookie(home_request, protect.session_cookie, signed <> "x")
  assert wisp.get_cookie(modified, protect.session_cookie, wisp.Signed)
    == Error(Nil)
  assert_signed_out(web.handle(modified, context))
  warden.stop(client)
  testing.stop_provider(provider)
}

pub fn validly_signed_unknown_session_references_are_refused_test() {
  let #(provider, client, context, home_request) = sign_in()
  let assert Ok(value) =
    wisp.get_cookie(home_request, protect.session_cookie, wisp.Signed)
  let assert Ok(issued) = list.last(string.split(value, "."))
  let unknown = "synthetic.unknown-reference." <> issued
  let assert Ok(issued_at) = int.parse(issued)
  assert protect.read_session_value(unknown, now: issued_at, max_age: 3600)
    == Ok("synthetic.unknown-reference")
  let signed = wisp.sign_message(home_request, <<unknown:utf8>>, crypto.Sha512)
  let modified =
    request.set_cookie(home_request, protect.session_cookie, signed)
  // Signature validity alone cannot grant access to a custody session.
  assert wisp.get_cookie(modified, protect.session_cookie, wisp.Signed)
    == Ok(unknown)
  assert_signed_out(web.handle(modified, context))
  warden.stop(client)
  testing.stop_provider(provider)
}

fn assert_signed_out(response: wisp.Response) {
  assert response.status == 200
  let assert wisp.Text(html) = response.body
  assert string.contains(html, "id=\"login\"")
  assert !string.contains(html, "id=\"subject\"")
  assert !string.contains(html, "id=\"email\"")
}

fn sign_in() -> #(testing.Provider, warden.Client, web.Context, wisp.Request) {
  let assert Ok(provider) =
    testing.start_provider(
      testing.provider_options() |> testing.with_login(testing.SignIn("ada")),
    )
  let origin = "https://" <> simulate.default_host
  let assert Ok(client) =
    warden.new(testing.config(provider, origin <> "/callback"))
  let assert Ok(Nil) = warden.start(client)
  let context =
    web.Context(
      client:,
      issuer: testing.issuer(provider),
      post_logout_redirect_uri: origin <> "/logged-out",
      origin:,
    )
  // GET /login: Warden's redirect and binding cookie.
  let login = simulate.browser_request(http.Get, "/login")
  let redirected = web.handle(login, context)
  assert redirected.status == 303
  let assert Ok(authorize) = list.key_find(redirected.headers, "location")
  assert string.starts_with(
    authorize,
    testing.issuer(provider) <> "/authorize?",
  )
  // The browser at the provider: the scripted login page redirects back.
  let assert Ok(#(303, headers, _)) =
    https(Get, authorize, "", testing.trust_anchor_pem(provider))
  let assert Ok(callback) = list.key_find(headers, "location")
  let assert Ok(#(_, path)) = string.split_once(callback, simulate.default_host)
  // GET /callback with the binding cookie: signed in.
  let callback_request =
    simulate.browser_request(http.Get, path)
    |> simulate.session(login, redirected)
  let signed_in = web.handle(callback_request, context)
  assert signed_in.status == 303
  assert list.key_find(signed_in.headers, "location") == Ok("/")
  let requests = testing.requests(provider)
  assert requests.authorizations == 1
  assert requests.code_grants == 1
  assert requests.userinfo == 1
  let home_request =
    simulate.browser_request(http.Get, "/")
    |> simulate.session(callback_request, signed_in)
  #(provider, client, context, home_request)
}
