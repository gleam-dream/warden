//// An HTTP-level login through the reference app's real routes: the
//// browser follows `/login` to the test provider's `/authorize` over
//// HTTPS and comes back to `/callback`. The app has no test hook; the
//// provider's scripted login page signs the user in.

import gleam/http
import gleam/list
import gleam/string
import warden
import warden/testing
import warden_reference/web
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
  let signed_in =
    web.handle(
      simulate.browser_request(http.Get, path)
        |> simulate.session(login, redirected),
      context,
    )
  assert signed_in.status == 303
  assert list.key_find(signed_in.headers, "location") == Ok("/")
  let requests = testing.requests(provider)
  assert requests.authorizations == 1
  assert requests.code_grants == 1
  assert requests.userinfo == 1
  warden.stop(client)
  testing.stop_provider(provider)
}
