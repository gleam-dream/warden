//// Reference relying party routes. Public Warden imports only.

import gleam/bit_array
import gleam/crypto
import gleam/dynamic/decode
import gleam/erlang/atom
import gleam/http
import gleam/http/response
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import warden
import warden/config
import warden_reference/protect
import wisp.{type Request, type Response}

pub type Context {
  Context(
    client: warden.Client,
    issuer: String,
    response_mode: config.ResponseMode,
    login_lifetime: Int,
    post_logout_redirect_uri: String,
    /// This application's origin, for the same-origin check on POSTs.
    origin: String,
  )
}

const binding_cookie = protect.binding_cookie

const session_cookie = protect.session_cookie

/// Server-side session lifetime, also the session cookie's Max-Age.
const session_max_age = 3600

pub fn handle(request: Request, context: Context) -> Response {
  use <- wisp.rescue_crashes
  protect.security_headers(route(request, context))
}

fn route(request: Request, context: Context) -> Response {
  case request.method, wisp.path_segments(request) {
    http.Get, [] -> home(request, context)
    http.Get, ["login"] -> login(request, context, None)
    http.Get, ["initiate-login"] -> third_party_initiated(request, context)
    http.Get, ["callback"] ->
      callback(request, context, warden.QueryCallback(query_string(request)))
    http.Post, ["callback"] -> {
      use body <- wisp.require_string_body(request)
      callback(request, context, warden.FormPostCallback(body))
    }
    http.Post, ["refresh"] -> {
      use <- same_origin(request, context)
      refresh(request, context)
    }
    http.Get, ["userinfo"] -> userinfo(request, context)
    http.Get, ["client-token"] -> client_token(request, context)
    http.Post, ["logout"] -> {
      use <- same_origin(request, context)
      logout(request, context)
    }
    http.Get, ["logged-out"] ->
      page(200, "Signed out", "<p>You are signed out.</p>")
    http.Get, ["health"] -> wisp.ok()
    // Front-channel logout is not implemented by Warden (explicit gap); the
    // route exists only so logout plans accept the client configuration.
    http.Get, ["frontchannel-logout"] -> wisp.ok()
    _, _ -> wisp.not_found()
  }
}

/// Refuse state-changing requests that do not come from this application's
/// own pages (cross-site request forgery).
fn same_origin(
  request: Request,
  context: Context,
  next: fn() -> Response,
) -> Response {
  case protect.same_origin(request, context.origin) {
    True -> next()
    False -> page(403, "Forbidden", "<p>Cross-site request refused.</p>")
  }
}

fn query_string(request: Request) -> String {
  option.unwrap(request.query, "")
}

// --- Login -------------------------------------------------------------------

fn login(request: Request, context: Context, hint: Option(String)) -> Response {
  let binding =
    wisp.get_cookie(request, binding_cookie, wisp.PlainText)
    |> result.try(warden.parse_browser_binding)
    |> option.from_result
  let options = warden.LoginOptions(..warden.default_login(), login_hint: hint)
  case warden.begin_login(context.client, binding, options) {
    Ok(redirect) ->
      wisp.redirect(redirect.url)
      |> set_binding(context, redirect.browser_binding)
    Error(error) ->
      page(503, "Sign-in unavailable", escape(string.inspect(error)))
  }
}

/// OpenID Connect third-party initiated login: accept only this issuer.
fn third_party_initiated(request: Request, context: Context) -> Response {
  let query = wisp.get_query(request)
  case list.key_find(query, "iss") {
    Ok(issuer) if issuer == context.issuer ->
      login(
        request,
        context,
        option.from_result(list.key_find(query, "login_hint")),
      )
    _ -> page(400, "Unknown issuer", "<p>Login initiation rejected.</p>")
  }
}

fn callback(
  request: Request,
  context: Context,
  input: warden.Callback,
) -> Response {
  let binding =
    wisp.get_cookie(request, binding_cookie, wisp.PlainText)
    |> result.try(warden.parse_browser_binding)
    |> option.from_result
  let completed = case warden.complete_login(context.client, input, binding) {
    Ok(warden.LoginCompleted(session)) -> Ok(session)
    Ok(warden.LoginRecoveryRequired(recovery)) ->
      case warden.recover_custody(context.client, recovery) {
        Ok(warden.CustodyRecovered(session)) -> Ok(session)
        _ -> Error(TryLater("sign-in could not be confirmed"))
      }
    Error(error) -> Error(login_failure(error))
  }
  case completed {
    Ok(session) ->
      // Userinfo is fetched after every login; a subject mismatch rejects it.
      case warden.userinfo(context.client, session) {
        Ok(_) | Error(warden.UserinfoNotSupported) ->
          wisp.redirect("/")
          |> response.set_cookie(
            session_cookie,
            wisp.sign_message(
              request,
              <<
                protect.session_value(
                  warden.session_reference(session),
                  issued_at: now_seconds(),
                ):utf8,
              >>,
              crypto.Sha512,
            ),
            protect.session_attributes(session_max_age),
          )
        Error(error) -> {
          let _ = warden.logout(context.client, session, no_redirect())
          failure_page(BadRequest(
            "userinfo rejected: " <> string.inspect(error),
          ))
        }
      }
    Error(failure) -> failure_page(failure)
  }
}

/// The application's own failure vocabulary.
pub type AppFailure {
  /// Start a new login; the old one cannot be resumed.
  RetryLogin(reason: String)
  /// The request itself is invalid or not ours.
  BadRequest(reason: String)
  /// A dependency is unavailable; retrying later may succeed.
  TryLater(reason: String)
}

/// Every Warden login error mapped explicitly (no catch-all).
pub fn login_failure(error: warden.LoginError) -> AppFailure {
  case error {
    warden.CallbackMalformed(problem) -> BadRequest(string.inspect(problem))
    warden.CallbackRejected(problem) -> BadRequest(string.inspect(problem))
    warden.LoginExpired -> RetryLogin("the sign-in took too long")
    warden.LoginReplayed -> RetryLogin("this sign-in was already used")
    warden.LoginChanged -> RetryLogin("the sign-in changed")
    warden.TransactionStoreUnavailable -> TryLater("sign-in store unavailable")
    warden.ProviderDenied(denial) -> RetryLogin(string.inspect(denial))
    warden.ProviderUnavailableBeforeExchange(_) ->
      RetryLogin("the identity provider was unreachable")
    warden.ExchangeRejected(error) -> RetryLogin(string.inspect(error))
    warden.ExchangeOutcomeUnknown -> RetryLogin("sign-in outcome unknown")
    warden.IdentityRejected(problem) -> RetryLogin(string.inspect(problem))
  }
}

fn failure_page(failure: AppFailure) -> Response {
  case failure {
    RetryLogin(reason) ->
      page(
        401,
        "Sign-in failed",
        "<p>"
          <> escape(reason)
          <> "</p><p><a href=\"/login\">Sign in again</a></p>",
      )
    BadRequest(reason) ->
      page(400, "Bad request", "<p>" <> escape(reason) <> "</p>")
    TryLater(reason) ->
      page(503, "Try again later", "<p>" <> escape(reason) <> "</p>")
  }
}

// --- Session -----------------------------------------------------------------

fn session(request: Request, context: Context) -> Result(warden.Session, Nil) {
  use value <- result.try(wisp.get_cookie(request, session_cookie, wisp.Signed))
  use reference <- result.try(protect.read_session_value(
    value,
    now: now_seconds(),
    max_age: session_max_age,
  ))
  warden.restore_session(context.client, reference) |> result.replace_error(Nil)
}

fn now_seconds() -> Int {
  system_time(atom.create("second"))
}

@external(erlang, "erlang", "system_time")
fn system_time(unit: atom.Atom) -> Int

/// A caller-owned claim type decoded from verified ID-token claims.
pub type Profile {
  Profile(department: Option(String), locale: Option(String))
}

pub fn profile_decoder() -> decode.Decoder(Profile) {
  use department <- decode.optional_field(
    "department",
    None,
    decode.optional(decode.string),
  )
  use locale <- decode.optional_field(
    "locale",
    None,
    decode.optional(decode.string),
  )
  decode.success(Profile(department:, locale:))
}

fn home(request: Request, context: Context) -> Response {
  case session(request, context) {
    Error(Nil) ->
      page(
        200,
        "Warden reference RP",
        "<p><a id=\"login\" href=\"/login\">Sign in</a></p>",
      )
    Ok(s) -> {
      let identity = warden.session_identity(s)
      let profile =
        warden.decode_claims(identity, profile_decoder())
        |> result.unwrap(Profile(None, None))
      page(
        200,
        "Signed in",
        "<dl><dt>Issuer</dt><dd id=\"issuer\">"
          <> escape(warden.issuer(identity))
          <> "</dd><dt>Subject</dt><dd id=\"subject\">"
          <> escape(warden.subject(identity))
          <> "</dd><dt>Email</dt><dd id=\"email\">"
          <> escape(option.unwrap(warden.email(identity), ""))
          <> "</dd><dt>Department</dt><dd id=\"department\">"
          <> escape(option.unwrap(profile.department, ""))
          <> "</dd><dt>Revision</dt><dd id=\"revision\">"
          <> string.inspect(warden.session_revision(s))
          <> "</dd></dl>"
          <> "<form method=\"post\" action=\"/refresh\"><button id=\"refresh\">Refresh</button></form>"
          <> "<form method=\"post\" action=\"/logout\"><button id=\"logout\">Sign out</button></form>",
      )
    }
  }
}

fn refresh(request: Request, context: Context) -> Response {
  case session(request, context) {
    Error(Nil) -> wisp.redirect("/")
    Ok(s) -> {
      let outcome = case warden.refresh_session(context.client, s) {
        Ok(warden.RefreshCompleted(refreshed)) ->
          case warden.userinfo(context.client, refreshed) {
            Ok(_) | Error(warden.UserinfoNotSupported) -> "completed"
            Error(_) -> "completed-userinfo-rejected"
          }
        Ok(warden.RefreshPublicationUnresolved(recovery)) ->
          case warden.recover_refresh_publication(context.client, recovery) {
            Ok(warden.RefreshCompleted(_)) -> "completed"
            _ -> "unresolved"
          }
        Ok(warden.RefreshDidNotSend(_)) -> "not-sent"
        Ok(warden.RefreshRejectedByEndpoint(_)) -> "rejected"
        Ok(warden.RefreshProviderQuarantined(_))
        | Ok(warden.RefreshResponseQuarantined(_, _))
        | Ok(warden.RefreshReservationUnresolved(_)) -> "quarantined"
        Error(error) -> "error:" <> string.inspect(error)
      }
      page(
        200,
        "Refresh",
        "<p id=\"refresh-outcome\">"
          <> escape(outcome)
          <> "</p><p><a href=\"/\">Back</a></p>",
      )
    }
  }
}

fn userinfo(request: Request, context: Context) -> Response {
  case session(request, context) {
    Error(Nil) -> wisp.response(401)
    Ok(s) ->
      case warden.userinfo(context.client, s) {
        Ok(info) ->
          wisp.json_response(
            "{\"sub\":\"" <> json_escape(warden.userinfo_subject(info)) <> "\"}",
            200,
          )
        Error(error) ->
          page(502, "Userinfo failed", escape(string.inspect(error)))
      }
  }
}

/// Signed-in users only: an anonymous route would let anyone spend the
/// client's credentials at the provider.
fn client_token(request: Request, context: Context) -> Response {
  use <- signed_in(request, context)
  case warden.client_credentials(context.client, []) {
    Ok(token) ->
      wisp.json_response(
        "{\"expires_in\":"
          <> option.unwrap(option.map(token.expires_in, string.inspect), "null")
          <> "}",
        200,
      )
    Error(error) ->
      page(502, "Client credentials failed", escape(string.inspect(error)))
  }
}

fn signed_in(
  request: Request,
  context: Context,
  next: fn() -> Response,
) -> Response {
  case session(request, context) {
    Ok(_) -> next()
    Error(Nil) -> wisp.response(401)
  }
}

fn logout(request: Request, context: Context) -> Response {
  let cleared = fn(response) {
    response.set_cookie(
      response,
      session_cookie,
      "",
      protect.session_attributes(0),
    )
  }
  case session(request, context) {
    Error(Nil) -> wisp.redirect("/logged-out") |> cleared
    Ok(s) -> {
      let options =
        warden.LogoutOptions(
          post_logout_redirect_uri: Some(context.post_logout_redirect_uri),
          state: Some(wisp.random_string(16)),
        )
      case warden.logout(context.client, s, options) {
        Ok(warden.RedirectToProvider(url)) -> wisp.redirect(url) |> cleared
        Ok(warden.NoEndSessionEndpoint) ->
          wisp.redirect("/logged-out") |> cleared
        Error(error) ->
          page(503, "Sign-out failed", escape(string.inspect(error)))
      }
    }
  }
}

fn no_redirect() -> warden.LogoutOptions {
  warden.LogoutOptions(post_logout_redirect_uri: None, state: None)
}

// --- Cookies and pages ---------------------------------------------------------

fn set_binding(
  response: Response,
  context: Context,
  binding: warden.BrowserBinding,
) -> Response {
  response.set_cookie(
    response,
    binding_cookie,
    wisp_plain(warden.browser_binding_value(binding)),
    protect.binding_attributes(context.response_mode, context.login_lifetime),
  )
}

/// wisp's PlainText cookies are base64 encoded; match that encoding so
/// `wisp.get_cookie(_, _, PlainText)` reads the value back.
fn wisp_plain(value: String) -> String {
  bit_array.base64_encode(<<value:utf8>>, False)
}

fn page(status: Int, title: String, body: String) -> Response {
  wisp.html_response(
    "<!doctype html><html><head><meta charset=\"utf-8\"><title>"
      <> escape(title)
      <> "</title></head><body><h1>"
      <> escape(title)
      <> "</h1>"
      <> body
      <> "</body></html>",
    status,
  )
}

fn escape(text: String) -> String {
  wisp.escape_html(text)
}

fn json_escape(text: String) -> String {
  text |> string.replace("\\", "\\\\") |> string.replace("\"", "\\\"")
}
