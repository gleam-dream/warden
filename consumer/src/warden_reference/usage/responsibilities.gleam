//// Usage: the decisions an application makes around Warden's evidence.
////
//// Warden owns checked OIDC and OAuth evidence and user-token custody. The
//// application chooses how those facts authorize its requests. Each function
//// below is one such decision, in the application's own types; the routes,
//// session cookie, CSRF and origin policy are in `warden_reference/web` and
//// `warden_reference/protect`. The design's "Application responsibilities"
//// section states every obligation.

import gleam/http/request
import gleam/option.{None, Some}
import gleam/result
import gleam/time/timestamp.{type Timestamp}
import warden
import warden/testing

/// `(issuer, subject)` is the authentication key. An email claim is neither
/// a stable identity key nor proof of permission.
pub fn identity_key(session: warden.Session) -> #(String, String) {
  let identity = warden.session_identity(session)
  #(warden.issuer(identity), warden.subject(identity))
}

/// What the application does about a failure. Warden's `Action` is closed,
/// so every case is handled.
pub type Handling {
  SendThroughLoginAgain
  TryTheSameOperationLater
  RunTheCarriedRecovery
  AlertAnOperator
  AnswerBadRequest
}

pub fn handle(action: warden.Action) -> Handling {
  case action {
    warden.Reauthenticate -> SendThroughLoginAgain
    warden.RetryLater -> TryTheSameOperationLater
    warden.Recover -> RunTheCarriedRecovery
    warden.FixConfiguration -> AlertAnOperator
    warden.RejectRequest -> AnswerBadRequest
  }
}

/// A forced `refresh` fits only where the application holds retry authority
/// for its own request. It does not make a resource-side effect idempotent.
pub fn call_resource(
  client: warden.Client,
  session: warden.Session,
  send: fn(String) -> Int,
  repeatable repeatable: Bool,
) -> Result(Int, warden.SessionError) {
  use access <- result.try(warden.access_token(client, session))
  let status = send(warden.access_token_value(access.token))
  case status, repeatable {
    401, True -> {
      use fresh <- result.map(warden.refresh(client, access.session))
      send(warden.access_token_value(fresh.token))
    }
    _, _ -> Ok(status)
  }
}

/// `client_credentials` grants one token per call and creates no session.
/// The application owns the cache policy, including an absent expiry.
pub type ServiceTokenCache {
  CacheUntil(Timestamp)
  DoNotCache
}

pub fn service_token_cache(token: warden.ClientToken) -> ServiceTokenCache {
  case token.expires_at {
    Some(expires_at) -> CacheUntil(expires_at)
    None -> DoNotCache
  }
}

/// Logout removes custody first. The application ends its own session
/// whatever happens, and reads revocation separately from custody removal.
pub type SignOut {
  SignOut(custody_removed: Bool, token_revoked: Bool)
}

pub fn end_session(client: warden.Client, session: warden.Session) -> SignOut {
  case warden.logout(client, session, warden.default_logout()) {
    Ok(warden.LoggedOut(revocation:, ..)) ->
      SignOut(
        custody_removed: True,
        token_revoked: revocation == warden.Revoked,
      )
    Error(_) -> SignOut(custody_removed: False, token_revoked: False)
  }
}

/// Runs each decision against the local test provider.
pub fn run() -> Nil {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  let assert Ok(client) =
    warden.new(testing.config(provider, "https://app.test/callback"))
  let assert Ok(Nil) = warden.start(client)
  let assert Ok(redirect) =
    warden.begin_login(client, request.new(), warden.default_login())
  let assert Ok(callback) =
    testing.authorize(provider, redirect, subject: "ada")
  let assert Ok(session) = warden.complete_login(client, callback)
  // The key names the user, whatever the email claims say.
  assert identity_key(session) == #(testing.issuer(provider), "ada")
  // Every action has a handling; failures map through the closed projections.
  assert handle(warden.login_error_action(warden.LoginReplayed))
    == SendThroughLoginAgain
  assert handle(warden.session_error_action(warden.SessionNotFound))
    == SendThroughLoginAgain
  assert handle(warden.RejectRequest) == AnswerBadRequest
  // A repeatable request refreshes once after a 401 and resends; a request
  // the application cannot repeat is answered as it came back.
  let assert Ok(access) = warden.access_token(client, session)
  let first = warden.access_token_value(access.token)
  let send = fn(token) {
    case token == first {
      True -> 401
      False -> 200
    }
  }
  assert call_resource(client, session, send, repeatable: True) == Ok(200)
  assert call_resource(client, session, fn(_) { 401 }, repeatable: False)
    == Ok(401)
  // A service grant carries its own expiry, and the application decides how
  // long to keep it.
  let assert Ok(service) = warden.new(testing.service_config(provider))
  let assert Ok(Nil) = warden.start(service)
  let assert Ok(granted) = warden.client_credentials(service, ["reports"])
  let assert CacheUntil(_) = service_token_cache(granted)
  assert service_token_cache(warden.ClientToken(..granted, expires_at: None))
    == DoNotCache
  // Logout removes custody, then revokes the refresh token.
  let assert Ok(current) =
    warden.restore_session(client, warden.session_reference(session))
  assert end_session(client, current)
    == SignOut(custody_removed: True, token_revoked: True)
  warden.stop(service)
  warden.stop(client)
  testing.stop_provider(provider)
}
