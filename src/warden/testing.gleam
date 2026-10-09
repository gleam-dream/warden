//// Test support: a scripted OpenID provider with its own test PKI, an
//// in-memory record store, and a conformance check for store adapters.
////
//// The provider serves discovery, keys, a scripted login page at
//// `/authorize`, token (authorization code with PKCE S256, rotating
//// refresh tokens, client credentials), userinfo, introspection,
//// revocation and end-session over HTTPS on loopback. Its certificate
//// chains to a root generated at start; `config` and `trusting` trust that
//// root and allow loopback explicitly, so no production default changes.
//// ID and access tokens are signed ES256 with gose.
////
//// ## Over HTTP
////
//// A test browser follows the application's login redirect to the
//// provider (trusting `trust_anchor_pem`). `/authorize` signs in the user
//// that `with_login` or `set_login` names (`test-user` by default, or the
//// request's `login_hint`) and answers `303` to the callback with `code`,
//// `state` and `iss` (a self-posting form for form-post). The application
//// needs no test hook:
////
//// ```gleam
//// let assert Ok(provider) =
////   testing.start_provider(
////     testing.provider_options() |> testing.with_login(testing.SignIn("ada")),
////   )
//// // The app runs `begin_login` and `login_response` in its /login route;
//// // the browser follows /login -> provider /authorize -> app /callback.
//// testing.set_login(provider, testing.Refuse("access_denied"))  // next login is cancelled
//// ```
////
//// ## In process
////
//// A unit test that holds the `LoginRedirect` skips HTTP:
////
//// ```gleam
//// let assert Ok(provider) = testing.start_provider(testing.provider_options())
//// let assert Ok(client) =
////   warden.new(testing.config(provider, "https://app.test/callback"))
//// let assert Ok(Nil) = warden.start(client)
////
//// let assert Ok(redirect) = warden.begin_login(client, browser, warden.default_login())
//// let assert Ok(callback) = testing.authorize(provider, redirect, subject: "ada")
//// let assert Ok(session) = warden.complete_login(client, callback)
//// ```
////
//// ## Access tokens
////
//// `set_access_token_audiences` changes the `aud` of issued access tokens
//// after start, so an application can name its own address once it
//// listens. `revoke_access_token` revokes one token for introspection and
//// userinfo; a local JWT validator (`warden/resource`) keeps accepting it
//// until it expires, as RFC 9068 tokens carry no revocation channel.
////
//// The provider mints tokens with keys it generated; nothing trusts them
//// unless a configuration names the provider's issuer and root.

import gleam/bit_array
import gleam/crypto
import gleam/dict.{type Dict}
import gleam/erlang/process.{type Subject}
import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/otp/actor
import gleam/result
import gleam/string
import gleam/time/duration.{type Duration}
import gleam/time/timestamp
import gleam/uri
import gose
import gose/jose/jwk
import gose/jose/jws
import gose/jose/jwt
import kryptos/ec
import warden.{type LoginRedirect}
import warden/config.{type Config}
import warden/internal/memory_store
import warden/internal/secure
import warden/internal/test_pki
import warden/internal/tls_server
import warden/store.{type Store, Record}

// ===========================================================================
// Options

/// How the provider behaves. Build from `provider_options()`.
pub opaque type ProviderOptions {
  ProviderOptions(
    client_id: String,
    client_secret: String,
    access_token_ttl: Int,
    access_token_audiences: List(String),
    refresh_delay_ms: Int,
    scopes: List(String),
    login: LoginDecision,
    granted_scopes: Dict(String, List(String)),
    email_claims: Dict(String, EmailClaims),
  )
}

/// What the provider's `/authorize` endpoint does with a browser that
/// arrives there: the provider's login page, scripted.
pub type LoginDecision {
  /// Sign `subject` in and redirect back to the client with a code. When
  /// the authorization request carries `login_hint` (Warden sends
  /// `LoginOptions.login_hint`), that subject signs in instead, so one
  /// provider serves several users at once.
  SignIn(subject: String)
  /// Redirect back with this OAuth error, as when the user cancels
  /// (`"access_denied"`) or `prompt=none` finds no session
  /// (`"login_required"`).
  Refuse(error: String)
}

/// Defaults: client `warden-test` with a random secret, five-minute access
/// tokens whose audience is the client id, no refresh delay, scopes
/// `openid email profile`, and `/authorize` signing in `test-user`.
pub fn provider_options() -> ProviderOptions {
  ProviderOptions(
    client_id: "warden-test",
    client_secret: secure.random_token(32),
    access_token_ttl: 300,
    access_token_audiences: [],
    refresh_delay_ms: 0,
    scopes: ["openid", "email", "profile"],
    login: SignIn("test-user"),
    granted_scopes: dict.new(),
    email_claims: dict.new(),
  )
}

/// What `/authorize` does; `set_login` changes it after start.
pub fn with_login(
  options: ProviderOptions,
  decision: LoginDecision,
) -> ProviderOptions {
  ProviderOptions(..options, login: decision)
}

/// Typed standard email claims. None omits that claim entirely. These are
/// provider assertions, not permission or email-format validation.
pub type EmailClaims {
  EmailClaims(email: Option(String), verified: Option(Bool))
}

/// Override only email claims for one subject in newly issued ID tokens and
/// userinfo. Without an override, the provider retains subject-derived email,
/// verified in ID tokens and no verification claim in userinfo.
/// Reserved protocol claims, identity constructors and production trust are unchanged.
pub fn with_email_claims(
  options: ProviderOptions,
  subject: String,
  claims: EmailClaims,
) -> ProviderOptions {
  ProviderOptions(
    ..options,
    email_claims: dict.insert(options.email_claims, subject, claims),
  )
}

/// The scopes a login of `subject` is granted, in place of the scopes the
/// client requested. The access token's `scope` claim, the token response
/// and introspection all carry exactly this list, so a test can sign in a
/// user who lacks a scope:
///
/// ```gleam
/// testing.provider_options()
/// |> testing.with_granted_scopes("ada", ["openid", "approve:refund"])
/// |> testing.with_granted_scopes("mallory", ["openid"])
/// ```
///
/// The list is granted whether or not the client requested it, and
/// `openid` is not added: list it if the test needs it. A subject without
/// an entry gets the scopes the client requested. The subject is the one
/// that signs in, so it also applies to a `login_hint`.
pub fn with_granted_scopes(
  options: ProviderOptions,
  subject: String,
  scopes: List(String),
) -> ProviderOptions {
  ProviderOptions(
    ..options,
    granted_scopes: dict.insert(options.granted_scopes, subject, scopes),
  )
}

/// The one registered client. It authenticates with `client_secret_basic`
/// or `client_secret_post`.
pub fn with_client(
  options: ProviderOptions,
  client_id client_id: String,
  secret secret: String,
) -> ProviderOptions {
  ProviderOptions(..options, client_id:, client_secret: secret)
}

/// Lifetime of access tokens issued by the token endpoint.
pub fn with_access_token_ttl(
  options: ProviderOptions,
  ttl: Duration,
) -> ProviderOptions {
  ProviderOptions(..options, access_token_ttl: whole_seconds(ttl))
}

/// `aud` of access tokens issued by the token endpoint. Default: the client
/// id. `set_access_token_audiences` changes it after start, for an audience
/// that names an address known only once the application listens.
pub fn with_access_token_audiences(
  options: ProviderOptions,
  audiences: List(String),
) -> ProviderOptions {
  ProviderOptions(..options, access_token_audiences: audiences)
}

/// Delay before answering a refresh grant, to widen refresh races.
pub fn with_refresh_delay(
  options: ProviderOptions,
  delay: Duration,
) -> ProviderOptions {
  ProviderOptions(..options, refresh_delay_ms: duration.to_milliseconds(delay))
}

fn whole_seconds(value: Duration) -> Int {
  let #(seconds, _) = duration.to_seconds_and_nanoseconds(value)
  seconds
}

// ===========================================================================
// Provider

pub opaque type Provider {
  Provider(
    issuer: String,
    ca_pem: String,
    ca_der: BitArray,
    server: tls_server.Server,
    state: Subject(Message),
    options: ProviderOptions,
  )
}

/// Requests the provider has answered, by kind.
pub type RequestCounts {
  RequestCounts(
    discovery: Int,
    /// Authorization requests, over HTTP or through `authorize`, whether
    /// they signed someone in or not.
    authorizations: Int,
    keys: Int,
    code_grants: Int,
    refresh_grants: Int,
    rejected_refresh_grants: Int,
    client_credentials_grants: Int,
    userinfo: Int,
    introspections: Int,
    revocations: Int,
    end_sessions: Int,
    /// Refresh tokens that are neither rotated nor revoked.
    active_refresh_tokens: Int,
  )
}

pub type TestError {
  /// The provider's PKI or listener did not start.
  ProviderStartFailed
  /// `authorize` was given a URL the provider does not accept (another
  /// client, no S256 challenge, or not this provider's endpoint).
  AuthorizationRefused(reason: String)
}

/// Start a provider on a free loopback port. It is linked to the caller, so
/// it ends with the test that started it; `stop_provider` ends it earlier.
pub fn start_provider(options: ProviderOptions) -> Result(Provider, TestError) {
  use pki <- result.try(
    test_pki.generate() |> result.replace_error(ProviderStartFailed),
  )
  use started <- result.try(
    actor.new(initial_state(options))
    |> actor.on_message(fn(state, message) {
      let Apply(change) = message
      actor.continue(change(state))
    })
    |> actor.start
    |> result.replace_error(ProviderStartFailed),
  )
  let state = started.data
  use server <- result.try(
    tls_server.start(pki, fn(request) { handle(state, request) })
    |> result.replace_error(ProviderStartFailed),
  )
  let issuer = "https://localhost:" <> int.to_string(server.port)
  transact(state, fn(s) { #(State(..s, issuer:), Nil) })
  Ok(Provider(
    issuer:,
    ca_pem: pki.ca_pem,
    ca_der: pki.ca_der,
    server:,
    state:,
    options:,
  ))
}

pub fn stop_provider(provider: Provider) -> Nil {
  tls_server.stop(provider.server)
  case process.subject_owner(provider.state) {
    Ok(pid) -> {
      process.unlink(pid)
      process.kill(pid)
    }
    Error(Nil) -> Nil
  }
}

pub fn issuer(provider: Provider) -> String {
  provider.issuer
}

pub fn client_id(provider: Provider) -> String {
  provider.options.client_id
}

/// PEM text of the provider's root certificate.
pub fn trust_anchor_pem(provider: Provider) -> String {
  provider.ca_pem
}

/// The provider's root certificate in DER, the form HTTP Gun's `Anchors`
/// takes, for a test client that calls the provider or the application over
/// HTTPS without Warden.
pub fn trust_anchor_der(provider: Provider) -> BitArray {
  provider.ca_der
}

/// A relying-party configuration for this provider: its issuer, client and
/// secret (`client_secret_basic`), its root, and loopback destinations.
pub fn config(provider: Provider, redirect_uri: String) -> Config {
  config.new(
    issuer: provider.issuer,
    client_id: provider.options.client_id,
    redirect_uri:,
    authentication: config.ClientSecretBasic(config.secret(
      provider.options.client_secret,
    )),
  )
  |> trusting(provider)
}

/// A service-client configuration for this provider (client credentials,
/// introspection).
pub fn service_config(provider: Provider) -> Config {
  config.service_client(
    issuer: provider.issuer,
    client_id: provider.options.client_id,
    authentication: config.ClientSecretBasic(config.secret(
      provider.options.client_secret,
    )),
  )
  |> trusting(provider)
}

/// Trust this provider's root and allow loopback destinations, on any
/// configuration (for example `config.resource_server`).
pub fn trusting(config: Config, provider: Provider) -> Config {
  config
  |> config.with_trust(config.TrustAnchorsPem(provider.ca_pem))
  |> config.with_destinations(config.AllowLoopbackForTesting)
}

pub fn requests(provider: Provider) -> RequestCounts {
  transact(provider.state, fn(s) {
    let active =
      dict.values(s.refresh_tokens)
      |> list.count(fn(grant) { grant.active })
    #(s, RequestCounts(..s.counts, active_refresh_tokens: active))
  })
}

/// Revoke every refresh token issued to `subject`, as an administrator
/// ending the grant would. The next refresh answers `invalid_grant`.
pub fn revoke_refresh_tokens(provider: Provider, subject: String) -> Nil {
  transact(provider.state, fn(s) {
    let refresh_tokens =
      dict.map_values(s.refresh_tokens, fn(_, grant) {
        case grant.subject == subject {
          True -> RefreshGrant(..grant, active: False)
          False -> grant
        }
      })
    #(State(..s, refresh_tokens:), Nil)
  })
}

/// Revoke one access token, as RFC 7009 revocation or an administrator
/// would. Introspection then answers `active: false` and userinfo
/// `invalid_token`.
///
/// A resource server that validates JWTs locally (`warden/resource`) does
/// not see this: RFC 9068 tokens carry no revocation channel, so they stay
/// valid until `exp`. A test that needs a revoked token refused at once
/// uses introspection (`warden.introspect`, or `resource`'s introspection
/// recipe); with local validation, use short lifetimes
/// (`with_access_token_ttl`).
pub fn revoke_access_token(provider: Provider, token: String) -> Nil {
  transact(provider.state, fn(s) {
    let access_tokens = case dict.get(s.access_tokens, token) {
      Ok(grant) ->
        dict.insert(s.access_tokens, token, AccessGrant(..grant, revoked: True))
      Error(Nil) -> s.access_tokens
    }
    #(State(..s, access_tokens:), Nil)
  })
}

/// `aud` of access tokens issued from now on (empty: the client id).
/// Tokens issued earlier keep theirs.
pub fn set_access_token_audiences(
  provider: Provider,
  audiences: List(String),
) -> Nil {
  transact(provider.state, fn(s) {
    let options =
      ProviderOptions(..s.options, access_token_audiences: audiences)
    #(State(..s, options:), Nil)
  })
}

/// What `/authorize` does from now on.
pub fn set_login(provider: Provider, decision: LoginDecision) -> Nil {
  transact(provider.state, fn(s) {
    #(State(..s, options: ProviderOptions(..s.options, login: decision)), Nil)
  })
}

/// Change one subject's assertions for future ID tokens and userinfo reads.
/// Previously issued tokens and verified identities remain unchanged.
pub fn set_email_claims(
  provider: Provider,
  subject: String,
  claims: EmailClaims,
) -> Nil {
  transact(provider.state, fn(s) {
    #(State(..s, options: with_email_claims(s.options, subject, claims)), Nil)
  })
}

/// What `with_granted_scopes` does, for logins from now on. An empty list
/// grants no scope at all.
pub fn set_granted_scopes(
  provider: Provider,
  subject: String,
  scopes: List(String),
) -> Nil {
  transact(provider.state, fn(s) {
    #(State(..s, options: with_granted_scopes(s.options, subject, scopes)), Nil)
  })
}

/// Make the provider's clock run ahead (positive) or behind: issued tokens
/// carry `iat` (and `auth_time`) shifted by `skew`.
pub fn set_clock_skew(provider: Provider, skew: Duration) -> Nil {
  transact(provider.state, fn(s) {
    #(State(..s, skew: whole_seconds(skew)), Nil)
  })
}

/// Replace the signing key with a new one (new `kid`). The key set lists the
/// new key first and keeps the previous one.
pub fn rotate_signing_key(provider: Provider) -> Nil {
  let key = new_key()
  transact(provider.state, fn(s) {
    #(State(..s, keys: [key, ..list.take(s.keys, 1)]), Nil)
  })
}

// ===========================================================================
// Browser front channel
//
// The provider serves `GET` and `POST /authorize` like a real login page
// whose user always answers as `LoginDecision` says: a test browser follows
// Warden's `login_url` there over HTTPS (trusting `trust_anchor_pem`) and
// is redirected back to the application's callback. `authorize` takes the
// same path in process, for tests that hold the `LoginRedirect`.

/// Play the browser and the provider's login page in process: accept the
/// authorization request in `redirect` for `subject` and return the
/// callback request Warden expects (the query, or a form post, with the
/// binding cookie). `subject` overrides the provider's `LoginDecision`.
pub fn authorize(
  provider: Provider,
  redirect: LoginRedirect,
  subject subject: String,
) -> Result(Request(String), TestError) {
  let url = warden.login_url(redirect)
  let endpoint = provider.issuer <> "/authorize?"
  use query <- result.try(case string.starts_with(url, endpoint) {
    True -> Ok(string.drop_start(url, string.length(endpoint)))
    False -> Error(AuthorizationRefused("not this provider's endpoint"))
  })
  use params <- result.try(
    uri.parse_query(query)
    |> result.replace_error(AuthorizationRefused("malformed query")),
  )
  use front <- result.try(
    authorization_front(provider.options.client_id, params)
    |> result.map_error(AuthorizationRefused),
  )
  let outcome =
    transact(provider.state, fn(s) {
      let s = count_authorization(s)
      case authorization_details(params) {
        Error(reason) -> #(s, Error(reason))
        Ok(details) -> {
          let #(s, code) = grant_code(s, subject, front, details)
          #(s, Ok(#(code, details.state, s.issuer)))
        }
      }
    })
  use #(code, state, issuer) <- result.try(
    outcome |> result.map_error(AuthorizationRefused),
  )
  let callback =
    uri.query_to_string([#("code", code), #("state", state), #("iss", issuer)])
  use target <- result.try(
    request.to(front.redirect_uri)
    |> result.replace_error(AuthorizationRefused("bad redirect_uri")),
  )
  let cookie = binding_cookie(redirect)
  let target = request.set_header(target, "cookie", cookie)
  case front.form_post {
    True ->
      Ok(
        target
        |> request.set_method(http.Post)
        |> request.set_header(
          "content-type",
          "application/x-www-form-urlencoded",
        )
        |> request.set_body(callback),
      )
    False ->
      Ok(
        request.Request(..target, query: Some(callback))
        |> request.set_body(""),
      )
  }
}

/// The parts of an authorization request that decide whether the provider
/// may redirect back at all (RFC 6749 §4.1.2.1: never to an unverified
/// redirect URI).
type AuthorizationFront {
  AuthorizationFront(redirect_uri: String, form_post: Bool)
}

type AuthorizationDetails {
  AuthorizationDetails(
    state: String,
    nonce: String,
    challenge: String,
    scopes: List(String),
    login_hint: Option(String),
  )
}

fn authorization_front(
  client_id: String,
  params: List(#(String, String)),
) -> Result(AuthorizationFront, String) {
  let param = fn(name) { list.key_find(params, name) }
  use _ <- result.try(case param("client_id") {
    Ok(id) if id == client_id -> Ok(Nil)
    _ -> Error("unknown client")
  })
  use redirect_uri <- result.try(
    param("redirect_uri") |> result.replace_error("no redirect_uri"),
  )
  use _ <- result.try(case uri.parse(redirect_uri) {
    Ok(uri.Uri(scheme: Some("https"), host: Some(_), fragment: None, ..))
    | Ok(uri.Uri(scheme: Some("http"), host: Some(_), fragment: None, ..)) ->
      Ok(Nil)
    _ -> Error("bad redirect_uri")
  })
  Ok(AuthorizationFront(
    redirect_uri:,
    form_post: param("response_mode") == Ok("form_post"),
  ))
}

fn authorization_details(
  params: List(#(String, String)),
) -> Result(AuthorizationDetails, String) {
  let param = fn(name) { list.key_find(params, name) }
  use _ <- result.try(case param("response_type") {
    Ok("code") -> Ok(Nil)
    _ -> Error("response_type is not code")
  })
  use _ <- result.try(case param("code_challenge_method") {
    Ok("S256") -> Ok(Nil)
    _ -> Error("no S256 challenge")
  })
  use challenge <- result.try(
    param("code_challenge") |> result.replace_error("no challenge"),
  )
  use state <- result.try(param("state") |> result.replace_error("no state"))
  use nonce <- result.try(param("nonce") |> result.replace_error("no nonce"))
  let scopes = case param("scope") {
    Ok(scope) -> string.split(scope, " ")
    Error(Nil) -> []
  }
  let login_hint = case param("login_hint") {
    Ok("") | Error(Nil) -> None
    Ok(hint) -> Some(hint)
  }
  Ok(AuthorizationDetails(state:, nonce:, challenge:, scopes:, login_hint:))
}

fn count_authorization(state: State) -> State {
  count(state, fn(c) {
    RequestCounts(..c, authorizations: c.authorizations + 1)
  })
}

/// Record a one-time code for `subject`.
fn grant_code(
  state: State,
  subject: String,
  front: AuthorizationFront,
  details: AuthorizationDetails,
) -> #(State, String) {
  let code = secure.random_token(24)
  let grant =
    CodeGrant(
      subject:,
      nonce: details.nonce,
      challenge: details.challenge,
      redirect_uri: front.redirect_uri,
      scopes: dict.get(state.options.granted_scopes, subject)
        |> result.unwrap(details.scopes),
      auth_time: now(state),
    )
  #(State(..state, codes: dict.insert(state.codes, code, grant)), code)
}

/// `GET` or `POST /authorize`: the scripted login page.
fn authorization_endpoint(
  state: Subject(Message),
  request: Request(String),
) -> Response(String) {
  let query = case request.method {
    http.Post -> request.body
    _ -> option.unwrap(request.query, "")
  }
  let params = uri.parse_query(query) |> result.unwrap([])
  let answer =
    transact(state, fn(s) {
      let s = count_authorization(s)
      case authorization_front(s.options.client_id, params) {
        Error(reason) -> #(s, Error(reason))
        Ok(front) -> {
          let state = list.key_find(params, "state")
          let #(s, callback) = case authorization_details(params) {
            Error(_) -> #(s, error_callback("invalid_request", state))
            Ok(details) ->
              case s.options.login {
                Refuse(error:) -> #(s, error_callback(error, state))
                SignIn(subject:) -> {
                  let subject = option.unwrap(details.login_hint, subject)
                  let #(s, code) = grant_code(s, subject, front, details)
                  #(s, [#("code", code), #("state", details.state)])
                }
              }
          }
          #(s, Ok(#(front, list.append(callback, [#("iss", s.issuer)]))))
        }
      }
    })
  case answer {
    // Never redirect to an unverified client or redirect URI.
    Error(reason) ->
      response.new(400)
      |> response.set_header("content-type", "text/plain")
      |> response.set_header("cache-control", "no-store")
      |> response.set_body("authorization refused: " <> reason)
    Ok(#(front, callback)) ->
      case front.form_post {
        True -> form_post_page(front.redirect_uri, callback)
        False -> {
          let separator = case string.contains(front.redirect_uri, "?") {
            True -> "&"
            False -> "?"
          }
          response.new(303)
          |> response.set_header(
            "location",
            front.redirect_uri <> separator <> uri.query_to_string(callback),
          )
          |> response.set_header("cache-control", "no-store")
          |> response.set_body("")
        }
      }
  }
}

fn error_callback(
  error: String,
  state: Result(String, Nil),
) -> List(#(String, String)) {
  case state {
    Ok(state) -> [#("error", error), #("state", state)]
    Error(Nil) -> [#("error", error)]
  }
}

/// OAuth 2.0 Form Post Response Mode: a page that posts the response to the
/// redirect URI. A scripted browser posts the form's fields itself.
fn form_post_page(
  redirect_uri: String,
  fields: List(#(String, String)),
) -> Response(String) {
  let inputs =
    list.map(fields, fn(field) {
      "<input type=\"hidden\" name=\""
      <> html_escape(field.0)
      <> "\" value=\""
      <> html_escape(field.1)
      <> "\">"
    })
    |> string.concat
  let body =
    "<!doctype html><html><body onload=\"document.forms[0].submit()\">"
    <> "<form method=\"post\" action=\""
    <> html_escape(redirect_uri)
    <> "\">"
    <> inputs
    <> "<noscript><button type=\"submit\">Continue</button></noscript>"
    <> "</form></body></html>"
  response.new(200)
  |> response.set_header("content-type", "text/html; charset=utf-8")
  |> response.set_header("cache-control", "no-store")
  |> response.set_body(body)
}

fn html_escape(text: String) -> String {
  text
  |> string.replace("&", "&amp;")
  |> string.replace("<", "&lt;")
  |> string.replace(">", "&gt;")
  |> string.replace("\"", "&quot;")
  |> string.replace("'", "&#39;")
}

/// The browser's binding cookie as Warden set it.
fn binding_cookie(redirect: LoginRedirect) -> String {
  warden.login_response(response.new(200), redirect).headers
  |> list.find_map(fn(header) {
    case header.0 == "set-cookie" {
      True ->
        case string.split_once(header.1, ";") {
          Ok(#(pair, _)) -> Ok(pair)
          Error(Nil) -> Ok(header.1)
        }
      False -> Error(Nil)
    }
  })
  |> result.unwrap("")
}

/// A request from the same browser (it carries the binding cookie of an
/// earlier login), for `warden.begin_login`.
pub fn browser_request(redirect: LoginRedirect) -> Request(String) {
  request.new() |> request.set_header("cookie", binding_cookie(redirect))
}

// ===========================================================================
// Minting access tokens

/// An access token to mint with `issue_access_token`. Build from
/// `access_token(subject)`.
pub opaque type TokenSpec {
  TokenSpec(
    subject: String,
    audiences: List(String),
    scopes: List(String),
    ttl: Int,
    issuer: Option(String),
    token_type: Option(String),
    forgery: Option(Forgery),
  )
}

/// A forged token, for testing that a resource server refuses it.
pub type Forgery {
  /// `alg: none` and an empty signature.
  UnsignedToken
  /// HS256 keyed with the provider's public key (algorithm confusion).
  HmacWithPublicKey
  /// Signed by a key the provider never published, with an unknown `kid`.
  UnknownKey
}

/// Defaults: audience the client id, no scopes, five minutes, `typ` `at+jwt`.
pub fn access_token(subject: String) -> TokenSpec {
  TokenSpec(
    subject:,
    audiences: [],
    scopes: [],
    ttl: 300,
    issuer: None,
    token_type: Some("at+jwt"),
    forgery: None,
  )
}

pub fn with_audiences(spec: TokenSpec, audiences: List(String)) -> TokenSpec {
  TokenSpec(..spec, audiences:)
}

pub fn with_scopes(spec: TokenSpec, scopes: List(String)) -> TokenSpec {
  TokenSpec(..spec, scopes:)
}

/// Lifetime from now; a negative value mints an expired token.
pub fn with_ttl(spec: TokenSpec, ttl: Duration) -> TokenSpec {
  TokenSpec(..spec, ttl: whole_seconds(ttl))
}

/// Claim another issuer.
pub fn with_issuer(spec: TokenSpec, issuer: String) -> TokenSpec {
  TokenSpec(..spec, issuer: Some(issuer))
}

/// The header `typ`; `None` omits it.
pub fn with_token_type(
  spec: TokenSpec,
  token_type: Option(String),
) -> TokenSpec {
  TokenSpec(..spec, token_type:)
}

pub fn forged(spec: TokenSpec, forgery: Forgery) -> TokenSpec {
  TokenSpec(..spec, forgery: Some(forgery))
}

/// Mint a JWT access token (RFC 9068) signed with the provider's current
/// key, or forged as `spec` says. The provider's introspection endpoint
/// knows it too.
pub fn issue_access_token(provider: Provider, spec: TokenSpec) -> String {
  transact(provider.state, fn(s) {
    let audiences = case spec.audiences {
      [] -> [s.options.client_id]
      audiences -> audiences
    }
    let iat = now(s)
    let claims =
      AccessClaims(
        issuer: option.unwrap(spec.issuer, s.issuer),
        subject: spec.subject,
        client_id: s.options.client_id,
        audiences:,
        scopes: spec.scopes,
        issued_at: iat,
        expires_at: iat + spec.ttl,
        jwt_id: secure.random_token(12),
      )
    let token = mint(s, claims, spec.token_type, spec.forgery)
    #(
      State(
        ..s,
        access_tokens: dict.insert(
          s.access_tokens,
          token,
          AccessGrant(claims:, revoked: False),
        ),
      ),
      token,
    )
  })
}

// ===========================================================================
// Stores

/// A fresh in-memory record store linked to the caller: a reference
/// implementation of the `warden/store` contract, for tests and for wrapping
/// with delays or failures.
pub fn memory_store() -> Store {
  let assert Ok(subject) = memory_store.start_linked(None)
  memory_store.store(subject, 5000)
}

/// Check a store adapter against the `warden/store` contract with records
/// under keys prefixed `warden-conformance:`: insert only when absent,
/// compare-and-set on the version, reads of the latest write, and
/// `delete_expired` deleting exactly the expired records. Returns every
/// violation found. Run it against an empty test table.
pub fn check_store(store: Store) -> Result(Nil, List(String)) {
  let prefix = "warden-conformance:" <> secure.random_token(6) <> ":"
  let at = fn(seconds) { timestamp.from_unix_seconds(seconds) }
  let past = at(1_000_000)
  let future = at(4_000_000_000)
  let record = fn(key, version, expires_at, bytes) {
    Record(key: prefix <> key, version:, expires_at:, sealed: bytes)
  }
  let checks = [
    #("get of an absent key is None", fn() {
      store.get(store, prefix <> "absent") == Ok(None)
    }),
    #("insert of an absent key writes", fn() {
      store.put(store, record("a", 1, future, <<1>>), None) == Ok(True)
    }),
    #("get returns the inserted record", fn() {
      store.get(store, prefix <> "a") == Ok(Some(record("a", 1, future, <<1>>)))
    }),
    #("insert of a present key is refused", fn() {
      store.put(store, record("a", 1, future, <<2>>), None) == Ok(False)
      && store.get(store, prefix <> "a")
      == Ok(Some(record("a", 1, future, <<1>>)))
    }),
    #("replace at the current version writes", fn() {
      store.put(store, record("a", 2, future, <<3>>), Some(1)) == Ok(True)
      && store.get(store, prefix <> "a")
      == Ok(Some(record("a", 2, future, <<3>>)))
    }),
    #("replace at a stale version is refused", fn() {
      store.put(store, record("a", 3, future, <<4>>), Some(1)) == Ok(False)
      && store.get(store, prefix <> "a")
      == Ok(Some(record("a", 2, future, <<3>>)))
    }),
    #("replace of an absent key is refused", fn() {
      store.put(store, record("b", 2, future, <<5>>), Some(1)) == Ok(False)
      && store.get(store, prefix <> "b") == Ok(None)
    }),
    #("binary payloads round-trip exactly", fn() {
      let bytes = crypto.strong_random_bytes(300)
      store.put(store, record("c", 1, future, bytes), None) == Ok(True)
      && store.get(store, prefix <> "c")
      == Ok(Some(record("c", 1, future, bytes)))
    }),
    #("delete_expired deletes expired records only", fn() {
      let assert Ok(True) = store.put(store, record("d", 1, past, <<6>>), None)
      case store.delete_expired(store, at(2_000_000)) {
        Ok(deleted) ->
          deleted >= 1
          && store.get(store, prefix <> "d") == Ok(None)
          && store.get(store, prefix <> "a")
          == Ok(Some(record("a", 2, future, <<3>>)))
        Error(_) -> False
      }
    }),
    #("a record expiring exactly at now is expired", fn() {
      let assert Ok(True) =
        store.put(store, record("e", 1, at(3_000_000), <<7>>), None)
      store.delete_expired(store, at(3_000_000)) |> result.is_ok
      && store.get(store, prefix <> "e") == Ok(None)
    }),
    #("concurrent inserts of one key: exactly one writes", fn() {
      let results =
        concurrently(list.repeat(
          fn() { store.put(store, record("f", 1, future, <<8>>), None) },
          8,
        ))
      list.count(results, fn(r) { r == Ok(True) }) == 1
      && list.count(results, fn(r) { r == Ok(False) }) == 7
    }),
    #("concurrent replaces at one version: exactly one writes", fn() {
      let results =
        concurrently(list.repeat(
          fn() { store.put(store, record("f", 2, future, <<9>>), Some(1)) },
          8,
        ))
      list.count(results, fn(r) { r == Ok(True) }) == 1
    }),
  ]
  let failures =
    list.filter_map(checks, fn(check) {
      case check.1() {
        True -> Error(Nil)
        False -> Ok(check.0)
      }
    })
  // Leave nothing behind.
  let _ = store.delete_expired(store, at(4_000_000_001))
  case failures {
    [] -> Ok(Nil)
    _ -> Error(failures)
  }
}

fn concurrently(work: List(fn() -> a)) -> List(a) {
  let reply = process.new_subject()
  let go = process.new_subject()
  let indexed = list.index_map(work, fn(run, index) { #(index, run) })
  list.each(indexed, fn(entry) {
    process.spawn(fn() {
      let start = process.new_subject()
      process.send(go, start)
      let _ = process.receive(start, 5000)
      process.send(reply, #(entry.0, entry.1()))
    })
  })
  let starters = list.filter_map(indexed, fn(_) { process.receive(go, 5000) })
  list.each(starters, fn(start) { process.send(start, Nil) })
  list.filter_map(indexed, fn(_) { process.receive(reply, 10_000) })
  |> list.sort(fn(a, b) { int.compare(a.0, b.0) })
  |> list.map(fn(pair) { pair.1 })
}

// ===========================================================================
// Provider state

type Message {
  Apply(fn(State) -> State)
}

fn transact(subject: Subject(Message), change: fn(State) -> #(State, a)) -> a {
  let reply = process.new_subject()
  process.send(
    subject,
    Apply(fn(state) {
      let #(state, answer) = change(state)
      process.send(reply, answer)
      state
    }),
  )
  let assert Ok(answer) = process.receive(reply, 10_000)
  answer
}

type SigningKey {
  SigningKey(kid: String, key: gose.Key(String))
}

type CodeGrant {
  CodeGrant(
    subject: String,
    nonce: String,
    challenge: String,
    redirect_uri: String,
    scopes: List(String),
    auth_time: Int,
  )
}

type RefreshGrant {
  RefreshGrant(
    subject: String,
    scopes: List(String),
    auth_time: Int,
    active: Bool,
  )
}

type AccessClaims {
  AccessClaims(
    issuer: String,
    subject: String,
    client_id: String,
    audiences: List(String),
    scopes: List(String),
    issued_at: Int,
    expires_at: Int,
    jwt_id: String,
  )
}

type AccessGrant {
  AccessGrant(claims: AccessClaims, revoked: Bool)
}

type State {
  State(
    issuer: String,
    options: ProviderOptions,
    keys: List(SigningKey),
    codes: Dict(String, CodeGrant),
    refresh_tokens: Dict(String, RefreshGrant),
    access_tokens: Dict(String, AccessGrant),
    skew: Int,
    counts: RequestCounts,
  )
}

fn initial_state(options: ProviderOptions) -> State {
  State(
    issuer: "",
    options:,
    keys: [new_key()],
    codes: dict.new(),
    refresh_tokens: dict.new(),
    access_tokens: dict.new(),
    skew: 0,
    counts: RequestCounts(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
  )
}

fn new_key() -> SigningKey {
  let kid = secure.random_token(9)
  let key =
    gose.generate_ec(ec.P256)
    |> gose.with_alg(gose.SigningAlg(es256()))
    |> gose.with_kid(kid)
  SigningKey(kid:, key:)
}

fn es256() -> gose.SigningAlg {
  gose.DigitalSignature(gose.Ecdsa(gose.EcdsaP256))
}

fn now(state: State) -> Int {
  secure.now_seconds() + state.skew
}

fn count(state: State, update: fn(RequestCounts) -> RequestCounts) -> State {
  State(..state, counts: update(state.counts))
}

// ===========================================================================
// HTTP

fn handle(
  state: Subject(Message),
  request: Request(String),
) -> Response(String) {
  case request.method, request.path {
    http.Get, "/.well-known/openid-configuration" -> {
      let issuer =
        transact(state, fn(s) {
          #(
            count(s, fn(c) { RequestCounts(..c, discovery: c.discovery + 1) }),
            s.issuer,
          )
        })
      json_response(200, discovery(issuer))
    }
    http.Get, "/jwks" -> {
      let keys =
        transact(state, fn(s) {
          #(count(s, fn(c) { RequestCounts(..c, keys: c.keys + 1) }), s.keys)
        })
      json_response(
        200,
        json.object([
          #(
            "keys",
            json.preprocessed_array(
              list.filter_map(keys, fn(k) {
                gose.public_key(k.key) |> result.map(jwk.to_json)
              }),
            ),
          ),
        ]),
      )
    }
    http.Get, "/authorize" | http.Post, "/authorize" ->
      authorization_endpoint(state, request)
    http.Post, "/token" -> token_endpoint(state, request)
    http.Get, "/userinfo" -> userinfo_endpoint(state, request)
    http.Post, "/introspect" -> introspection_endpoint(state, request)
    http.Post, "/revoke" -> revocation_endpoint(state, request)
    http.Get, "/logout" -> {
      transact(state, fn(s) {
        #(
          count(s, fn(c) {
            RequestCounts(..c, end_sessions: c.end_sessions + 1)
          }),
          Nil,
        )
      })
      response.new(200) |> response.set_body("signed out")
    }
    _, _ -> oauth_error(404, "not_found")
  }
}

fn discovery(issuer: String) -> json.Json {
  let strings = fn(values) { json.array(values, json.string) }
  json.object([
    #("issuer", json.string(issuer)),
    #("authorization_endpoint", json.string(issuer <> "/authorize")),
    #("token_endpoint", json.string(issuer <> "/token")),
    #("userinfo_endpoint", json.string(issuer <> "/userinfo")),
    #("introspection_endpoint", json.string(issuer <> "/introspect")),
    #("revocation_endpoint", json.string(issuer <> "/revoke")),
    #("end_session_endpoint", json.string(issuer <> "/logout")),
    #("jwks_uri", json.string(issuer <> "/jwks")),
    #("response_types_supported", strings(["code"])),
    #("response_modes_supported", strings(["query", "form_post"])),
    #(
      "grant_types_supported",
      strings(["authorization_code", "refresh_token", "client_credentials"]),
    ),
    #("subject_types_supported", strings(["public"])),
    #("scopes_supported", strings(["openid", "email", "profile"])),
    #("id_token_signing_alg_values_supported", strings(["ES256"])),
    #("code_challenge_methods_supported", strings(["S256"])),
    #(
      "token_endpoint_auth_methods_supported",
      strings(["client_secret_basic", "client_secret_post"]),
    ),
    #("authorization_response_iss_parameter_supported", json.bool(True)),
  ])
}

fn form(request: Request(String)) -> List(#(String, String)) {
  uri.parse_query(request.body) |> result.unwrap([])
}

/// `client_secret_basic` or `client_secret_post` with the registered
/// client.
fn client_authenticated(
  options: ProviderOptions,
  request: Request(String),
  form: List(#(String, String)),
) -> Bool {
  let basic =
    "Basic "
    <> bit_array.base64_encode(
      <<
        {
          uri.percent_encode(options.client_id)
          <> ":"
          <> uri.percent_encode(options.client_secret)
        }:utf8,
      >>,
      True,
    )
  case request.get_header(request, "authorization") {
    Ok(value) -> value == basic
    Error(Nil) ->
      list.key_find(form, "client_id") == Ok(options.client_id)
      && list.key_find(form, "client_secret") == Ok(options.client_secret)
  }
}

fn token_endpoint(
  state: Subject(Message),
  request: Request(String),
) -> Response(String) {
  let form = form(request)
  let field = fn(name) { list.key_find(form, name) }
  let options = transact(state, fn(s) { #(s, s.options) })
  case client_authenticated(options, request, form) {
    False -> oauth_error(401, "invalid_client")
    True ->
      case field("grant_type") {
        Ok("authorization_code") -> code_grant(state, field)
        Ok("refresh_token") -> {
          process.sleep(options.refresh_delay_ms)
          refresh_grant(state, field)
        }
        Ok("client_credentials") -> {
          let scopes = case field("scope") {
            Ok(scope) -> string.split(scope, " ")
            Error(Nil) -> []
          }
          let token =
            transact(state, fn(s) {
              let s =
                count(s, fn(c) {
                  RequestCounts(
                    ..c,
                    client_credentials_grants: c.client_credentials_grants + 1,
                  )
                })
              issue(s, s.options.client_id, scopes)
            })
          json_response(
            200,
            json.object([
              #("access_token", json.string(token)),
              #("token_type", json.string("Bearer")),
              #("expires_in", json.int(options.access_token_ttl)),
              #("scope", json.string(string.join(scopes, " "))),
            ]),
          )
        }
        _ -> oauth_error(400, "unsupported_grant_type")
      }
  }
}

fn code_grant(
  state: Subject(Message),
  field: fn(String) -> Result(String, Nil),
) -> Response(String) {
  case field("code"), field("code_verifier"), field("redirect_uri") {
    Ok(code), Ok(verifier), Ok(redirect_uri) -> {
      let challenge = secure.s256(verifier)
      let issued =
        transact(state, fn(s) {
          let s =
            count(s, fn(c) {
              RequestCounts(..c, code_grants: c.code_grants + 1)
            })
          case dict.get(s.codes, code) {
            Ok(grant)
              if grant.redirect_uri == redirect_uri
              && grant.challenge == challenge
            -> {
              let s = State(..s, codes: dict.delete(s.codes, code))
              let #(s, access) = issue(s, grant.subject, grant.scopes)
              let refresh = secure.random_token(24)
              let s =
                State(
                  ..s,
                  refresh_tokens: dict.insert(
                    s.refresh_tokens,
                    refresh,
                    RefreshGrant(
                      subject: grant.subject,
                      scopes: grant.scopes,
                      auth_time: grant.auth_time,
                      active: True,
                    ),
                  ),
                )
              let id_token = id_token(s, grant)
              #(s, Ok(#(access, refresh, id_token, grant.scopes)))
            }
            _ -> #(State(..s, codes: dict.delete(s.codes, code)), Error(Nil))
          }
        })
      case issued {
        Ok(#(access, refresh, id_token, scopes)) ->
          tokens_response(state, access, refresh, Some(id_token), scopes)
        Error(Nil) -> oauth_error(400, "invalid_grant")
      }
    }
    _, _, _ -> oauth_error(400, "invalid_request")
  }
}

fn refresh_grant(
  state: Subject(Message),
  field: fn(String) -> Result(String, Nil),
) -> Response(String) {
  case field("refresh_token") {
    Error(Nil) -> oauth_error(400, "invalid_request")
    Ok(presented) -> {
      let issued =
        transact(state, fn(s) {
          case dict.get(s.refresh_tokens, presented) {
            Ok(RefreshGrant(active: True, ..) as grant) -> {
              let s =
                count(s, fn(c) {
                  RequestCounts(..c, refresh_grants: c.refresh_grants + 1)
                })
              let #(s, access) = issue(s, grant.subject, grant.scopes)
              let refresh = secure.random_token(24)
              let tokens =
                s.refresh_tokens
                |> dict.insert(presented, RefreshGrant(..grant, active: False))
                |> dict.insert(refresh, grant)
              #(
                State(..s, refresh_tokens: tokens),
                Ok(#(access, refresh, grant.scopes)),
              )
            }
            _ -> #(
              count(s, fn(c) {
                RequestCounts(
                  ..c,
                  rejected_refresh_grants: c.rejected_refresh_grants + 1,
                )
              }),
              Error(Nil),
            )
          }
        })
      case issued {
        // OIDC Core §12.2: the refresh response may omit the ID token.
        Ok(#(access, refresh, scopes)) ->
          tokens_response(state, access, refresh, None, scopes)
        Error(Nil) -> oauth_error(400, "invalid_grant")
      }
    }
  }
}

fn tokens_response(
  state: Subject(Message),
  access: String,
  refresh: String,
  id_token: Option(String),
  scopes: List(String),
) -> Response(String) {
  let ttl = transact(state, fn(s) { #(s, s.options.access_token_ttl) })
  let fields = [
    #("access_token", json.string(access)),
    #("token_type", json.string("Bearer")),
    #("expires_in", json.int(ttl)),
    #("refresh_token", json.string(refresh)),
    #("scope", json.string(string.join(scopes, " "))),
  ]
  let fields = case id_token {
    Some(token) -> [#("id_token", json.string(token)), ..fields]
    None -> fields
  }
  json_response(200, json.object(fields))
}

/// Mint and record an access token for `subject`.
fn issue(
  state: State,
  subject: String,
  scopes: List(String),
) -> #(State, String) {
  let iat = now(state)
  let audiences = case state.options.access_token_audiences {
    [] -> [state.options.client_id]
    audiences -> audiences
  }
  let claims =
    AccessClaims(
      issuer: state.issuer,
      subject:,
      client_id: state.options.client_id,
      audiences:,
      scopes: list.filter(scopes, fn(s) { s != "" }),
      issued_at: iat,
      expires_at: iat + state.options.access_token_ttl,
      jwt_id: secure.random_token(12),
    )
  let token = mint(state, claims, Some("at+jwt"), None)
  #(
    State(
      ..state,
      access_tokens: dict.insert(
        state.access_tokens,
        token,
        AccessGrant(claims:, revoked: False),
      ),
    ),
    token,
  )
}

fn id_token(state: State, grant: CodeGrant) -> String {
  let iat = now(state)
  let assert [SigningKey(key:, ..), ..] = state.keys
  let claims =
    jwt.claims()
    |> jwt.with_issuer(state.issuer)
    |> jwt.with_subject(grant.subject)
    |> jwt.with_audience(state.options.client_id)
    |> jwt.with_issued_at(timestamp.from_unix_seconds(iat))
    |> jwt.with_expiration(timestamp.from_unix_seconds(iat + 600))
  let claims =
    [
      #("nonce", json.string(grant.nonce)),
      #("auth_time", json.int(grant.auth_time)),
    ]
    |> list.append(email_fields(state.options, grant.subject, Some(True)))
    |> list.fold(claims, fn(claims, pair) {
      let assert Ok(claims) = jwt.with_claim(claims, key: pair.0, value: pair.1)
      claims
    })
  let assert Ok(signed) = jwt.sign(es256(), claims, key)
  jwt.serialize(signed)
}

fn email_fields(
  options: ProviderOptions,
  subject: String,
  default_verified: Option(Bool),
) -> List(#(String, json.Json)) {
  let claims =
    dict.get(options.email_claims, subject)
    |> result.unwrap(EmailClaims(
      Some(subject <> "@example.test"),
      default_verified,
    ))
  let fields = case claims.email {
    Some(email) -> [#("email", json.string(email))]
    None -> []
  }
  case claims.verified {
    Some(verified) ->
      list.append(fields, [#("email_verified", json.bool(verified))])
    None -> fields
  }
}

fn access_claims_json(claims: AccessClaims) -> List(#(String, json.Json)) {
  [
    #("iss", json.string(claims.issuer)),
    #("sub", json.string(claims.subject)),
    #("client_id", json.string(claims.client_id)),
    #("aud", json.array(claims.audiences, json.string)),
    #("scope", json.string(string.join(claims.scopes, " "))),
    #("iat", json.int(claims.issued_at)),
    #("exp", json.int(claims.expires_at)),
    #("jti", json.string(claims.jwt_id)),
  ]
}

fn mint(
  state: State,
  claims: AccessClaims,
  token_type: Option(String),
  forgery: Option(Forgery),
) -> String {
  let assert [SigningKey(kid:, key:), ..] = state.keys
  let payload = json.to_string(json.object(access_claims_json(claims)))
  let header = fn(alg, kid) {
    [#("alg", json.string(alg))]
    |> list.append(case kid {
      Some(kid) -> [#("kid", json.string(kid))]
      None -> []
    })
    |> list.append(case token_type {
      Some(typ) -> [#("typ", json.string(typ))]
      None -> []
    })
    |> json.object
    |> json.to_string
  }
  case forgery {
    Some(UnsignedToken) ->
      segment(header("none", None)) <> "." <> segment(payload) <> "."
    Some(HmacWithPublicKey) -> {
      let assert Ok(public) = gose.public_key(key)
      let secret = json.to_string(jwk.to_json(public))
      let input = segment(header("HS256", Some(kid))) <> "." <> segment(payload)
      let mac = crypto.hmac(<<input:utf8>>, crypto.Sha256, <<secret:utf8>>)
      input <> "." <> bit_array.base64_url_encode(mac, False)
    }
    Some(UnknownKey) ->
      sign_es256(new_key().key, "unknown-key", token_type, payload)
    None -> sign_es256(key, kid, token_type, payload)
  }
}

fn sign_es256(
  key: gose.Key(String),
  kid: String,
  token_type: Option(String),
  payload: String,
) -> String {
  let unsigned = jws.new(es256()) |> jws.with_kid(kid)
  let unsigned = case token_type {
    Some(typ) -> jws.with_typ(unsigned, typ)
    None -> unsigned
  }
  let assert Ok(signed) = jws.sign(unsigned, key:, payload: <<payload:utf8>>)
  let assert Ok(token) = jws.serialize_compact(signed)
  token
}

fn segment(text: String) -> String {
  bit_array.base64_url_encode(<<text:utf8>>, False)
}

fn bearer(request: Request(String)) -> Result(String, Nil) {
  case request.get_header(request, "authorization") {
    Ok("Bearer " <> token) -> Ok(token)
    _ -> Error(Nil)
  }
}

fn userinfo_endpoint(
  state: Subject(Message),
  request: Request(String),
) -> Response(String) {
  let found =
    transact(state, fn(s) {
      let s = count(s, fn(c) { RequestCounts(..c, userinfo: c.userinfo + 1) })
      let fields =
        live_access(s, bearer(request))
        |> result.map(fn(claims) {
          [
            #("sub", json.string(claims.subject)),
            ..email_fields(s.options, claims.subject, None)
          ]
        })
      #(s, fields)
    })
  case found {
    Ok(fields) -> json_response(200, json.object(fields))
    Error(Nil) -> oauth_error(401, "invalid_token")
  }
}

fn live_access(
  state: State,
  token: Result(String, Nil),
) -> Result(AccessClaims, Nil) {
  use token <- result.try(token)
  let current = now(state)
  case dict.get(state.access_tokens, token) {
    Ok(AccessGrant(claims:, revoked: False)) if claims.expires_at > current ->
      Ok(claims)
    _ -> Error(Nil)
  }
}

fn introspection_endpoint(
  state: Subject(Message),
  request: Request(String),
) -> Response(String) {
  let form = form(request)
  let result =
    transact(state, fn(s) {
      let s =
        count(s, fn(c) {
          RequestCounts(..c, introspections: c.introspections + 1)
        })
      case client_authenticated(s.options, request, form) {
        False -> #(s, Error(Nil))
        True -> #(s, Ok(live_access(s, list.key_find(form, "token"))))
      }
    })
  case result {
    Error(Nil) -> oauth_error(401, "invalid_client")
    Ok(Error(Nil)) ->
      json_response(200, json.object([#("active", json.bool(False))]))
    Ok(Ok(claims)) ->
      json_response(
        200,
        json.object([
          #("active", json.bool(True)),
          #("token_type", json.string("Bearer")),
          ..access_claims_json(claims)
        ]),
      )
  }
}

fn revocation_endpoint(
  state: Subject(Message),
  request: Request(String),
) -> Response(String) {
  let form = form(request)
  let authorized =
    transact(state, fn(s) {
      let s =
        count(s, fn(c) { RequestCounts(..c, revocations: c.revocations + 1) })
      case
        client_authenticated(s.options, request, form),
        list.key_find(form, "token")
      {
        True, Ok(token) -> {
          let refresh_tokens = case dict.get(s.refresh_tokens, token) {
            Ok(grant) ->
              dict.insert(
                s.refresh_tokens,
                token,
                RefreshGrant(..grant, active: False),
              )
            Error(Nil) -> s.refresh_tokens
          }
          let access_tokens = case dict.get(s.access_tokens, token) {
            Ok(grant) ->
              dict.insert(
                s.access_tokens,
                token,
                AccessGrant(..grant, revoked: True),
              )
            Error(Nil) -> s.access_tokens
          }
          #(State(..s, refresh_tokens:, access_tokens:), True)
        }
        True, Error(Nil) -> #(s, True)
        False, _ -> #(s, False)
      }
    })
  case authorized {
    // RFC 7009 §2.2: 200 whether or not the token was known.
    True -> response.new(200) |> response.set_body("")
    False -> oauth_error(401, "invalid_client")
  }
}

fn json_response(status: Int, body: json.Json) -> Response(String) {
  response.new(status)
  |> response.set_header("content-type", "application/json")
  |> response.set_header("cache-control", "no-store")
  |> response.set_body(json.to_string(body))
}

fn oauth_error(status: Int, code: String) -> Response(String) {
  json_response(status, json.object([#("error", json.string(code))]))
}
