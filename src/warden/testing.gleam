//// Test support: a scripted OpenID provider with its own test PKI, an
//// in-memory record store, and a conformance check for store adapters.
////
//// The provider serves discovery, keys, token (authorization code with
//// PKCE S256, rotating refresh tokens, client credentials), userinfo,
//// introspection, revocation and end-session over HTTPS on loopback. Its
//// certificate chains to a root generated at start; `config` and `trusting`
//// trust that root and allow loopback explicitly, so no production default
//// changes. ID and access tokens are signed ES256 with gose.
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
  )
}

/// Defaults: client `warden-test` with a random secret, five-minute access
/// tokens whose audience is the client id, no refresh delay, scopes
/// `openid email profile`.
pub fn provider_options() -> ProviderOptions {
  ProviderOptions(
    client_id: "warden-test",
    client_secret: secure.random_token(32),
    access_token_ttl: 300,
    access_token_audiences: [],
    refresh_delay_ms: 0,
    scopes: ["openid", "email", "profile"],
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

/// `aud` of access tokens issued by the token endpoint.
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
    server: tls_server.Server,
    state: Subject(Message),
    options: ProviderOptions,
  )
}

/// Requests the provider has answered, by kind.
pub type RequestCounts {
  RequestCounts(
    discovery: Int,
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
  Ok(Provider(issuer:, ca_pem: pki.ca_pem, server:, state:, options:))
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

/// Play the browser and the provider's login page: accept the authorization
/// request in `redirect` for `subject` and return the callback request
/// Warden expects (the query, or a form post, with the binding cookie).
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
  let param = fn(name) { list.key_find(params, name) }
  use _ <- result.try(case param("client_id") {
    Ok(id) if id == provider.options.client_id -> Ok(Nil)
    _ -> Error(AuthorizationRefused("unknown client"))
  })
  use _ <- result.try(case param("code_challenge_method") {
    Ok("S256") -> Ok(Nil)
    _ -> Error(AuthorizationRefused("no S256 challenge"))
  })
  use challenge <- result.try(
    param("code_challenge")
    |> result.replace_error(AuthorizationRefused("no challenge")),
  )
  use state <- result.try(
    param("state") |> result.replace_error(AuthorizationRefused("no state")),
  )
  use nonce <- result.try(
    param("nonce") |> result.replace_error(AuthorizationRefused("no nonce")),
  )
  use redirect_uri <- result.try(
    param("redirect_uri")
    |> result.replace_error(AuthorizationRefused("no redirect_uri")),
  )
  let scopes = case param("scope") {
    Ok(scope) -> string.split(scope, " ")
    Error(Nil) -> []
  }
  let code = secure.random_token(24)
  transact(provider.state, fn(s) {
    let grant =
      CodeGrant(
        subject:,
        nonce:,
        challenge:,
        redirect_uri:,
        scopes:,
        auth_time: now(s),
      )
    #(State(..s, codes: dict.insert(s.codes, code, grant)), Nil)
  })
  let callback =
    uri.query_to_string([
      #("code", code),
      #("state", state),
      #("iss", provider.issuer),
    ])
  use target <- result.try(
    request.to(redirect_uri)
    |> result.replace_error(AuthorizationRefused("bad redirect_uri")),
  )
  let cookie = binding_cookie(redirect)
  let target = request.set_header(target, "cookie", cookie)
  case param("response_mode") {
    Ok("form_post") ->
      Ok(
        target
        |> request.set_method(http.Post)
        |> request.set_header(
          "content-type",
          "application/x-www-form-urlencoded",
        )
        |> request.set_body(callback),
      )
    _ ->
      Ok(
        request.Request(..target, query: Some(callback))
        |> request.set_body(""),
      )
  }
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
    counts: RequestCounts(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
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
      #("email", json.string(grant.subject <> "@example.test")),
      #("email_verified", json.bool(True)),
    ]
    |> list.fold(claims, fn(claims, pair) {
      let assert Ok(claims) = jwt.with_claim(claims, key: pair.0, value: pair.1)
      claims
    })
  let assert Ok(signed) = jwt.sign(es256(), claims, key)
  jwt.serialize(signed)
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
      #(s, live_access(s, bearer(request)))
    })
  case found {
    Ok(claims) ->
      json_response(
        200,
        json.object([
          #("sub", json.string(claims.subject)),
          #("email", json.string(claims.subject <> "@example.test")),
        ]),
      )
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
