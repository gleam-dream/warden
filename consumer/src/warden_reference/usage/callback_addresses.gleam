//// Usage: one client served under several registered callback addresses.
////
//// One URI given to `config.new` serves most applications. An application
//// served under several registered callback addresses lists the others, and
//// each login picks one. The match is exact and anything else fails closed.
//// The authorization code is exchanged with the URI the login chose. Every
//// allowed URI must be registered at the provider, and all of them are fixed
//// when `warden.new` runs.

import gleam/http/request
import gleam/option.{Some}
import warden
import warden/config
import warden/testing

// snips-start: callback-addresses
const admin_callback = "https://admin.example.com/callback"

pub fn allow_admin_callback(configuration: config.Config) -> config.Config {
  configuration
  |> config.with_allowed_redirect_uris([admin_callback])
}

/// GET /admin/login
pub fn admin_login(
  client: warden.Client,
  req: request.Request(a),
) -> Result(warden.LoginRedirect, warden.LoginError) {
  let options =
    warden.LoginOptions(
      ..warden.default_login(),
      redirect_uri: Some(admin_callback),
    )
  warden.begin_login(client, req, options)
}

// snips-end: callback-addresses

/// A login completes at the chosen callback address; a near miss such as a
/// trailing slash is refused before any provider request.
pub fn run() -> Nil {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  let admin = "https://admin.app.test/callback"
  let assert Ok(client) =
    warden.new(
      testing.config(provider, "https://app.test/callback")
      |> config.with_allowed_redirect_uris([admin]),
    )
  let assert Ok(Nil) = warden.start(client)
  let options = fn(uri) {
    warden.LoginOptions(..warden.default_login(), redirect_uri: Some(uri))
  }
  let assert Ok(redirect) =
    warden.begin_login(client, request.new(), options(admin))
  let assert Ok(callback) =
    testing.authorize(provider, redirect, subject: "ada")
  assert callback.host == "admin.app.test"
  let assert Ok(_) = warden.complete_login(client, callback)
  let assert Error(error) =
    warden.begin_login(client, request.new(), options(admin <> "/"))
  assert error == warden.InvalidLoginOption(warden.RedirectUriNotAllowed)
  assert warden.login_error_action(error) == warden.FixConfiguration
  // The shown helpers build on the same types.
  assert allow_admin_callback(testing.config(provider, "https://app.test/cb"))
    |> config.validate
    == Ok(Nil)
  warden.stop(client)
  testing.stop_provider(provider)
}
