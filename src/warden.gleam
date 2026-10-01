//// Warden: a typed OpenID Connect relying party and OAuth client.
////
//// This module is the canonical owner of verified identity and sessions. A
//// `VerifiedIdentity` exists only after a configured backend verified an ID
//// token for a login transaction this module consumed atomically, and after
//// this module compared the verified issuer, audience, authorized party,
//// subject and nonce with that transaction. A `Session` exists only after the
//// custody owner confirmed installation of that identity and its tokens.
////
//// ```gleam
//// let assert Ok(cfg) = config.validate(settings)
//// let assert Ok(client) = warden.start(cfg)
////
//// // Login start: redirect the browser, store the binding in a cookie.
//// let assert Ok(redirect) = warden.begin_login(client, None, warden.default_login())
////
//// // Callback: pass the raw query (or form body) and the cookie value.
//// case warden.complete_login(client, warden.QueryCallback(query), Some(binding)) {
////   Ok(warden.LoginCompleted(session)) -> ...
////   Ok(warden.LoginRecoveryRequired(recovery)) -> ...
////   Error(error) -> ...
//// }
//// ```

import gleam/bit_array
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/erlang/process.{type Pid}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/otp/actor
import gleam/otp/static_supervisor as supervisor
import gleam/otp/supervision
import gleam/result
import gleam/set
import gleam/string
import gleam/uri
import warden/config.{type Config}
import warden/internal/call
import warden/internal/callback
import warden/internal/custody_store as custody
import warden/internal/native/client as native
import warden/internal/native/provider
import warden/internal/protocol
import warden/internal/redacted.{type Redacted}
import warden/internal/secure
import warden/internal/transaction_store as transactions
import warden/internal/transport

// ===========================================================================
// Client lifecycle

/// A started Warden client: provider worker, transaction store and custody
/// owner under one supervisor.
pub opaque type Client {
  Client(
    config: Config,
    backend: native.Client,
    transactions: transactions.Store,
    custody: custody.Store(VerifiedIdentity),
    provider: String,
    supervisor: Pid,
    clock: fn() -> Int,
    provider_name: Dynamic,
  )
}

pub type StartError {
  /// Discovery through Warden's transport failed.
  DiscoveryFailed(ProviderFailure)
  /// The provider's metadata is incompatible with Warden's policy.
  ProviderIncompatible(List(Incompatibility))
  /// Metadata or keys did not load within `startup_timeout_ms`.
  StartupTimedOut
  /// A Warden process failed to start.
  ProcessStartFailed
}

pub type Incompatibility {
  /// The provider does not advertise PKCE `S256` (with
  /// `AssumeS256WhenUnadvertised`: it lists other methods only).
  NoS256
  AuthorizationCodeGrantUnsupported
  /// The configured response mode is not advertised.
  ResponseModeUnsupported
  /// The configured client authentication method is not advertised.
  AuthenticationMethodUnsupported
  /// No configured ID-token algorithm is advertised.
  NoCommonSigningAlgorithm
  /// No configured client-assertion algorithm is advertised.
  NoCommonAssertionAlgorithm
  /// The provider requires pushed authorization requests (a later
  /// capability).
  RequiresPushedAuthorization
  /// The provider requires signed request objects (a later capability).
  RequiresRequestObjects
  /// The authorization endpoint is not an absolute `https` URI.
  InsecureAuthorizationEndpoint
  /// The end-session endpoint is not an absolute `https` URI.
  InsecureEndSessionEndpoint
  MissingTokenEndpoint
}

/// A provider interaction failure, without provider content.
pub type ProviderFailure {
  /// Metadata or keys are not loaded; nothing was sent.
  ProviderNotReady
  /// Transport failure. `sent` is False only when no request byte can have
  /// reached the provider.
  TransportFailure(sent: Bool, reason: TransportReason)
  /// The provider answered with an error status.
  ProviderStatus(status: Int, error: OAuthError)
  /// The provider's response could not be used.
  MalformedProviderResponse
  /// The provider's metadata issuer differs from the configured issuer.
  IssuerMismatch
  /// A backend failure Warden does not classify further.
  UnclassifiedBackendFailure
}

pub type TransportReason {
  DestinationRejected
  InsecureScheme
  InvalidDestination
  ResolutionFailed
  ConnectionRefused
  ConnectionFailed
  TlsRejected
  Timeout
  ResponseTooLarge
  ResponseHeadersTooLarge
  MalformedHttp
  TruncatedResponse
  UnsupportedContentEncoding
  OtherTransportFailure
}

/// OAuth error codes from provider error responses. Descriptions and URIs
/// are discarded.
pub type OAuthError {
  InvalidRequest
  InvalidClient
  InvalidGrant
  UnauthorizedClient
  UnsupportedGrantType
  InvalidScope
  InvalidToken
  InsufficientScope
  OtherOAuthError
  NoOAuthError
}

/// Start a Warden client: discover the provider, check its metadata against
/// the validated configuration, and start the supervised processes. The
/// supervisor is linked to the caller.
pub fn start(config: Config) -> Result(Client, StartError) {
  start_with_clock(config, secure.now_seconds)
}

/// A child specification for an application supervision tree.
pub fn supervised(config: Config) -> supervision.ChildSpecification(Client) {
  supervision.supervisor(fn() {
    case start(config) {
      Ok(client) -> Ok(actor.Started(pid: client.supervisor, data: client))
      Error(_) -> Error(actor.InitFailed("warden failed to start"))
    }
  })
}

/// Stop the client's supervisor and every process under it.
pub fn stop(client: Client) -> Nil {
  process.unlink(client.supervisor)
  process.send_abnormal_exit(client.supervisor, Shutdown)
}

type ExitReason {
  Shutdown
}

@internal
pub fn start_with_clock(
  config: Config,
  clock: fn() -> Int,
) -> Result(Client, StartError) {
  use _ <- result.try(case secure.ensure_applications() {
    True -> Ok(Nil)
    False -> Error(ProcessStartFailed)
  })
  let issuer = config.issuer(config)
  let policy = config.transport_policy(config)
  // One discovery and JWKS load within startup_timeout_ms; the provider
  // cache starts from it.
  let deadline = transport.monotonic_ms() + config.startup_timeout_ms(config)
  use discovered <- result.try(
    provider.discover(issuer, policy, deadline)
    |> result.map_error(fn(f) {
      case transport.monotonic_ms() >= deadline {
        True -> StartupTimedOut
        False -> DiscoveryFailed(provider_failure(f))
      }
    }),
  )
  use _ <- result.try(case compatibility(config, discovered.metadata) {
    [] -> Ok(Nil)
    problems -> Error(ProviderIncompatible(problems))
  })
  let provider_name = process.new_name("warden_provider")
  let timeout = config.store_timeout_ms(config)
  let provider_handle =
    provider.Provider(process.named_subject(provider_name), timeout)
  start_supervised(
    config,
    clock,
    supervision.worker(fn() {
      provider.start(provider_name, issuer, policy, Some(discovered))
      |> result.map(fn(started) { actor.Started(..started, data: Nil) })
    }),
    native.new(config, provider_handle, policy, clock),
    to_dynamic(provider_name),
  )
}

fn start_supervised(
  config: Config,
  clock: fn() -> Int,
  provider_child: supervision.ChildSpecification(Nil),
  backend: native.Client,
  provider_name: Dynamic,
) -> Result(Client, StartError) {
  let transaction_name = process.new_name("warden_transactions")
  let custody_name = process.new_name("warden_custody")
  let lifetime = config.login_lifetime_seconds(config)
  let started =
    supervisor.new(supervisor.OneForOne)
    |> supervisor.restart_tolerance(intensity: 10, period: 60)
    |> supervisor.add(provider_child)
    |> supervisor.add(
      supervision.worker(fn() {
        transactions.start(
          clock:,
          capacity: config.max_pending_logins(config),
          retention: lifetime,
          name: transaction_name,
        )
      }),
    )
    |> supervisor.add(
      supervision.worker(fn() {
        custody.start(
          new_reference: fn() { secure.random_token(32) },
          history_limit: 100_000,
          name: custody_name,
        )
      }),
    )
    |> supervisor.start
  case started {
    Error(_) -> Error(ProcessStartFailed)
    Ok(actor.Started(pid: supervisor_pid, ..)) -> {
      let timeout = config.store_timeout_ms(config)
      Ok(Client(
        config:,
        backend:,
        transactions: transactions.Store(
          process.named_subject(transaction_name),
          timeout,
        ),
        custody: custody.Store(process.named_subject(custody_name), timeout),
        provider: provider_binding(config),
        supervisor: supervisor_pid,
        clock:,
        provider_name:,
      ))
    }
  }
}

@external(erlang, "gleam_stdlib", "identity")
fn to_dynamic(value: a) -> Dynamic

fn provider_binding(config: Config) -> String {
  config.issuer(config) <> " " <> config.client_id(config)
}

fn compatibility(
  config: Config,
  metadata: protocol.Metadata,
) -> List(Incompatibility) {
  let assume_s256 =
    config.pkce_advertisement(config) == config.AssumeS256WhenUnadvertised
  let method = config.authentication_method(config)
  let assertion_algorithms = config.assertion_algorithms(config)
  let checks = [
    #(
      case metadata.code_challenge_methods {
        Some(methods) -> list.contains(methods, "S256")
        // Omitted entirely: acceptable only under the explicit opt-in.
        None -> assume_s256
      },
      NoS256,
    ),
    #(
      list.contains(metadata.grant_types, "authorization_code"),
      AuthorizationCodeGrantUnsupported,
    ),
    #(
      list.contains(
        metadata.response_modes,
        response_mode_name(config.response_mode(config)),
      ),
      ResponseModeUnsupported,
    ),
    #(
      list.contains(metadata.auth_methods, method),
      AuthenticationMethodUnsupported,
    ),
    #(
      list.any(config.signing_algorithms(config), list.contains(
        metadata.id_token_algorithms,
        _,
      )),
      NoCommonSigningAlgorithm,
    ),
    #(
      assertion_algorithms == []
        || list.any(assertion_algorithms, list.contains(
        metadata.auth_signing_algorithms,
        _,
      )),
      NoCommonAssertionAlgorithm,
    ),
    #(!metadata.requires_par, RequiresPushedAuthorization),
    #(!metadata.requires_signed_request_object, RequiresRequestObjects),
    #(https_uri(metadata.authorization_endpoint), InsecureAuthorizationEndpoint),
    #(
      option.map(metadata.end_session_endpoint, https_uri)
        |> option.unwrap(True),
      InsecureEndSessionEndpoint,
    ),
    #(option.is_some(metadata.token_endpoint), MissingTokenEndpoint),
  ]
  list.filter_map(checks, fn(check) {
    case check.0 {
      True -> Error(Nil)
      False -> Ok(check.1)
    }
  })
}

fn https_uri(value: String) -> Bool {
  case uri.parse(value) {
    Ok(uri.Uri(scheme: Some("https"), host: Some(host), fragment: None, ..)) ->
      host != ""
    _ -> False
  }
}

fn response_mode_name(mode: config.ResponseMode) -> String {
  case mode {
    config.Query -> "query"
    config.FormPost -> "form_post"
  }
}

// ===========================================================================
// Login start

/// A browser binding: a random value the application stores in a cookie
/// (`HttpOnly`, `Secure`) when login starts and presents at the callback.
/// Transactions store only its digest. One binding may cover several
/// concurrent logins (tabs) of the same browser.
pub opaque type BrowserBinding {
  BrowserBinding(value: Redacted(String))
}

/// The cookie value for a binding.
pub fn browser_binding_value(binding: BrowserBinding) -> String {
  redacted.reveal(binding.value)
}

/// Accept a cookie value as a browser binding. Only values of the shape
/// Warden generates (43 base64url characters) are accepted.
pub fn parse_browser_binding(value: String) -> Result(BrowserBinding, Nil) {
  case string.length(value) == 43 && base64url_only(value) {
    True -> Ok(BrowserBinding(redacted.new(value)))
    False -> Error(Nil)
  }
}

fn base64url_only(value: String) -> Bool {
  value
  |> bit_array.from_string
  |> all_bytes(fn(b) {
    { b >= 0x41 && b <= 0x5A }
    || { b >= 0x61 && b <= 0x7A }
    || { b >= 0x30 && b <= 0x39 }
    || b == 0x2D
    || b == 0x5F
  })
}

fn all_bytes(bytes: BitArray, check: fn(Int) -> Bool) -> Bool {
  case bytes {
    <<>> -> True
    <<b, rest:bytes>> -> check(b) && all_bytes(rest, check)
    _ -> False
  }
}

pub type Prompt {
  PromptNone
  PromptLogin
  PromptConsent
  PromptSelectAccount
}

pub type LoginOptions {
  LoginOptions(
    /// Scopes added to the configured scopes for this login.
    scopes: List(String),
    prompt: List(Prompt),
    /// Maximum authentication age in seconds. When set, the ID token must
    /// carry `auth_time` within this age.
    max_age: Option(Int),
    login_hint: Option(String),
    acr_values: List(String),
    ui_locales: List(String),
    /// Extension parameters. Reserved OAuth/OIDC parameter names are
    /// rejected.
    extra_parameters: List(#(String, String)),
  )
}

pub fn default_login() -> LoginOptions {
  LoginOptions(
    scopes: [],
    prompt: [],
    max_age: None,
    login_hint: None,
    acr_values: [],
    ui_locales: [],
    extra_parameters: [],
  )
}

pub type LoginRedirect {
  LoginRedirect(
    /// The provider authorization URL to redirect the browser to.
    url: String,
    /// Store this binding in a cookie; present it at the callback.
    browser_binding: BrowserBinding,
  )
}

pub type BeginLoginError {
  InvalidLoginOption(LoginOptionProblem)
  /// Provider metadata is unavailable or no longer compatible.
  LoginProviderUnavailable(ProviderFailure)
  LoginProviderIncompatible(List(Incompatibility))
  /// The transaction store did not confirm the new login.
  LoginStoreUnavailable
  /// The transaction store is at capacity.
  TooManyPendingLogins
}

pub type LoginOptionProblem {
  InvalidOptionScope(String)
  ReservedParameter(String)
  InvalidParameterValue(String)
  InvalidMaxAge
}

const reserved_parameters = [
  "response_type", "client_id", "redirect_uri", "state", "nonce", "scope",
  "code_challenge", "code_challenge_method", "response_mode", "request",
  "request_uri", "prompt", "max_age", "login_hint", "acr_values", "ui_locales",
  "claims", "dpop_jkt", "iss", "code_verifier", "client_secret",
  "client_assertion", "client_assertion_type", "registration", "id_token_hint",
]

/// Begin a login: generate state, nonce and PKCE verifier from the OS
/// CSPRNG, store the pending transaction and return the authorization URL.
/// Pass the browser's existing binding to keep concurrent tabs bound to one
/// cookie.
pub fn begin_login(
  client: Client,
  browser: Option(BrowserBinding),
  options: LoginOptions,
) -> Result(LoginRedirect, BeginLoginError) {
  use extension <- result.try(
    login_extension(options) |> result.map_error(InvalidLoginOption),
  )
  use metadata <- result.try(
    native.metadata(client.backend)
    |> result.map_error(fn(f) { LoginProviderUnavailable(provider_failure(f)) }),
  )
  use _ <- result.try(case compatibility(client.config, metadata) {
    [] -> Ok(Nil)
    problems -> Error(LoginProviderIncompatible(problems))
  })
  let binding = case browser {
    Some(binding) -> binding
    None -> BrowserBinding(redacted.new(secure.random_token(32)))
  }
  let state = secure.random_token(32)
  let nonce = secure.random_token(32)
  let verifier = secure.random_token(32)
  let redirect_uri = config.redirect_uri(client.config)
  let scopes =
    list.append(config.scopes(client.config), options.scopes) |> list.unique
  let mode = response_mode_name(config.response_mode(client.config))
  use url <- result.try(
    native.authorization_url(
      client.backend,
      protocol.AuthorizationParams(
        redirect_uri:,
        state:,
        nonce:,
        verifier:,
        scopes:,
        response_mode: mode,
        extension:,
      ),
    )
    |> result.map_error(fn(f) { LoginProviderUnavailable(provider_failure(f)) }),
  )
  use _ <- result.try(check_authorization_url(
    url,
    metadata.authorization_endpoint,
    state:,
    nonce:,
    challenge: secure.s256(verifier),
    redirect_uri:,
    client_id: config.client_id(client.config),
  ))
  let now = client.clock()
  let material =
    transactions.Material(
      state:,
      nonce:,
      verifier:,
      redirect_uri:,
      browser_hash: secure.sha256_hex(redacted.reveal(binding.value)),
      max_age: options.max_age,
      created_at: now,
      expires_at: now + config.login_lifetime_seconds(client.config),
    )
  case transactions.put(client.transactions, transaction_key(state), material) {
    Ok(transactions.Stored(_)) ->
      Ok(LoginRedirect(url:, browser_binding: binding))
    Ok(transactions.CapacityExceeded) -> Error(TooManyPendingLogins)
    Error(_) -> Error(LoginStoreUnavailable)
  }
}

fn login_extension(
  options: LoginOptions,
) -> Result(List(#(String, String)), LoginOptionProblem) {
  use _ <- result.try(
    list.try_each(options.scopes, fn(scope) {
      case config.valid_scope(scope) {
        True -> Ok(Nil)
        False -> Error(InvalidOptionScope(scope))
      }
    }),
  )
  use _ <- result.try(
    list.try_each(options.extra_parameters, fn(param) {
      case list.contains(reserved_parameters, string.lowercase(param.0)) {
        True -> Error(ReservedParameter(param.0))
        False ->
          case param.0 != "" && printable(param.0) && printable(param.1) {
            True -> Ok(Nil)
            False -> Error(InvalidParameterValue(param.0))
          }
      }
    }),
  )
  use _ <- result.try(case options.max_age {
    Some(age) if age < 0 -> Error(InvalidMaxAge)
    _ -> Ok(Nil)
  })
  use values <- result.try(
    list.try_map(
      [
        #("login_hint", option.unwrap(options.login_hint, "")),
        #("acr_values", string.join(options.acr_values, " ")),
        #("ui_locales", string.join(options.ui_locales, " ")),
      ],
      fn(pair) {
        case printable(pair.1) {
          True -> Ok(pair)
          False -> Error(InvalidParameterValue(pair.0))
        }
      },
    ),
  )
  let prompt =
    options.prompt
    |> list.map(fn(p) {
      case p {
        PromptNone -> "none"
        PromptLogin -> "login"
        PromptConsent -> "consent"
        PromptSelectAccount -> "select_account"
      }
    })
    |> list.unique
    |> string.join(" ")
  let max_age = case options.max_age {
    Some(age) -> int.to_string(age)
    None -> ""
  }
  [#("prompt", prompt), #("max_age", max_age), ..values]
  |> list.filter(fn(pair) { pair.1 != "" })
  |> list.append(options.extra_parameters)
  |> Ok
}

fn printable(value: String) -> Bool {
  value
  |> bit_array.from_string
  |> all_bytes(fn(b) { b >= 0x20 && b != 0x7F })
}

/// Defence in depth: the authorization URL must target the discovered
/// authorization endpoint and carry exactly Warden's state, nonce, redirect
/// URI and S256 challenge, with no request object or request URI.
fn check_authorization_url(
  url: String,
  endpoint: String,
  state state: String,
  nonce nonce: String,
  challenge challenge: String,
  redirect_uri redirect_uri: String,
  client_id client_id: String,
) -> Result(Nil, BeginLoginError) {
  let incompatible = Error(LoginProviderIncompatible([NoS256]))
  // The endpoint may carry its own query; Warden's parameters follow it.
  let prefix = case string.contains(endpoint, "?") {
    True -> endpoint <> "&"
    False -> endpoint <> "?"
  }
  case string.starts_with(url, prefix) {
    False -> incompatible
    True ->
      case uri.parse_query(string.drop_start(url, string.length(prefix))) {
        Ok(params) -> {
          let expect = fn(key, value) {
            list.filter(params, fn(p) { p.0 == key }) == [#(key, value)]
          }
          case
            expect("state", state)
            && expect("nonce", nonce)
            && expect("code_challenge", challenge)
            && expect("code_challenge_method", "S256")
            && expect("redirect_uri", redirect_uri)
            && expect("client_id", client_id)
            && expect("response_type", "code")
            && !list.any(params, fn(p) {
              p.0 == "request" || p.0 == "request_uri"
            })
          {
            True -> Ok(Nil)
            False -> incompatible
          }
        }
        Error(Nil) -> incompatible
      }
  }
}

fn transaction_key(state: String) -> String {
  secure.sha256_hex(state)
}

// ===========================================================================
// Login completion

/// The raw authorization response as received by the application.
pub type Callback {
  /// The query string of a redirect to the callback (without `?`).
  QueryCallback(String)
  /// The `application/x-www-form-urlencoded` body of a form-post callback.
  FormPostCallback(String)
}

pub type LoginCompletion {
  LoginCompleted(Session)
  /// Identity was verified and custody installation was submitted, but its
  /// outcome is unknown. Call `recover_custody`; the authorization code is
  /// never exchanged again.
  LoginRecoveryRequired(CustodyRecovery)
}

pub type LoginError {
  /// The callback is not a well-formed authorization response. No
  /// transaction was touched.
  CallbackMalformed(CallbackProblem)
  /// The callback does not match a pending login of this browser. No
  /// transaction was consumed.
  CallbackRejected(BindingProblem)
  /// The login expired before its callback was consumed.
  LoginExpired
  /// The login was already consumed by another callback.
  LoginReplayed
  /// The stored login changed between check and consumption.
  LoginChanged
  /// The transaction store did not answer; the login may or may not have
  /// been consumed. Nothing was sent to the provider.
  TransactionStoreUnavailable
  /// The provider returned an error response; the login is consumed.
  ProviderDenied(Denial)
  /// The token request was proven not to have been sent. The login is
  /// consumed; start a new login.
  ProviderUnavailableBeforeExchange(ProviderFailure)
  /// The token endpoint rejected the exchange.
  ExchangeRejected(OAuthError)
  /// The exchange may have reached the provider but its outcome is unknown.
  /// The code is never retried; start a new login.
  ExchangeOutcomeUnknown
  /// Tokens were returned but the identity was not accepted.
  IdentityRejected(IdentityProblem)
}

pub type CallbackProblem {
  CallbackTooLarge
  CallbackEncodingInvalid
  DuplicateCallbackParameter
  MissingState
  MissingCode
  EmptyCode
  /// Both `code` and `error` are present.
  AmbiguousCallback
  InvalidCallbackValue
  /// A query callback arrived while form-post is configured, or the reverse.
  UnexpectedResponseMode
}

pub type BindingProblem {
  /// No pending login has this state.
  UnknownState
  /// The browser binding cookie is absent.
  BrowserBindingMissing
  /// The browser binding does not belong to this login.
  BrowserBindingMismatch
  /// `iss` differs from the configured issuer (RFC 9207).
  CallbackIssuerMismatch
  /// `iss` is required by policy but absent.
  CallbackIssuerMissing
}

/// Provider error codes (RFC 6749 §4.1.2.1, OIDC Core §3.1.2.6).
/// Descriptions are discarded.
pub type Denial {
  AccessDenied
  LoginRequired
  ConsentRequired
  InteractionRequired
  AccountSelectionRequired
  TemporarilyUnavailable
  ServerError
  InvalidRequestDenial
  UnauthorizedClientDenial
  UnsupportedResponseType
  InvalidScopeDenial
  OtherDenial
}

pub type IdentityProblem {
  /// The token response had no ID token.
  MissingIdToken
  BadSignature
  /// The ID token uses an algorithm outside the configured allowlist.
  AlgorithmNotAllowed
  /// `alg: none`.
  UnsignedIdToken
  /// An encrypted ID token without a nested signature.
  EncryptedUnsignedIdToken
  /// Encrypted ID tokens are not supported.
  EncryptedIdTokenUnsupported
  /// The signing key is unknown even after refreshing the provider keys.
  UnknownSigningKey
  IdTokenIssuerMismatch
  IdTokenAudienceMismatch
  AuthorizedPartyMismatch
  IdTokenExpired
  IdTokenNotYetValid
  NonceMismatch
  AccessTokenHashMismatch
  MissingClaim(String)
  SubjectMismatch
  /// `max_age` was requested and `auth_time` is absent or too old.
  AuthenticationTooOld
  MalformedIdToken
  UnclassifiedIdentityFailure
}

/// Complete a login from the raw callback and the browser's binding.
///
/// Order: parse strictly; find the pending login by state; compare state,
/// browser binding and issuer without consuming; consume atomically; only a
/// consumption confirmed by the store proceeds to exchange the code; verify
/// the identity; install custody.
pub fn complete_login(
  client: Client,
  callback: Callback,
  browser: Option(BrowserBinding),
) -> Result(LoginCompletion, LoginError) {
  use parsed <- result.try(parse_callback(client, callback))
  let state = case parsed {
    callback.CodeResponse(state:, ..) | callback.ErrorResponse(state:, ..) ->
      state
  }
  let key = transaction_key(state)
  use lookup <- result.try(
    transactions.get(client.transactions, key)
    |> result.replace_error(TransactionStoreUnavailable),
  )
  use #(material, revision) <- result.try(case lookup {
    transactions.Found(material:, revision:) -> Ok(#(material, revision))
    transactions.FoundConsumed -> Error(LoginReplayed)
    transactions.FoundExpired -> Error(LoginExpired)
    transactions.NotFound -> Error(CallbackRejected(UnknownState))
  })
  use _ <- result.try(check_binding(client, parsed, material, browser))
  use decision <- result.try(
    transactions.consume(client.transactions, key, revision)
    |> result.replace_error(TransactionStoreUnavailable),
  )
  use material <- result.try(case decision {
    transactions.Consumed(material) -> Ok(material)
    transactions.AlreadyConsumed -> Error(LoginReplayed)
    transactions.Expired -> Error(LoginExpired)
    transactions.Changed -> Error(LoginChanged)
    transactions.Missing -> Error(CallbackRejected(UnknownState))
  })
  case parsed {
    callback.ErrorResponse(error:, ..) -> Error(ProviderDenied(denial(error)))
    callback.CodeResponse(code:, ..) -> exchange(client, material, code)
  }
}

fn parse_callback(
  client: Client,
  callback: Callback,
) -> Result(callback.Parsed, LoginError) {
  let #(raw, form, expected) = case callback {
    QueryCallback(raw) -> #(raw, False, config.Query)
    FormPostCallback(raw) -> #(raw, True, config.FormPost)
  }
  case config.response_mode(client.config) == expected {
    False -> Error(CallbackMalformed(UnexpectedResponseMode))
    True ->
      callback.parse(raw, form)
      |> result.map_error(fn(problem) {
        CallbackMalformed(case problem {
          callback.InputTooLarge -> CallbackTooLarge
          callback.InvalidEncoding -> CallbackEncodingInvalid
          callback.DuplicateParameter -> DuplicateCallbackParameter
          callback.MissingState -> MissingState
          callback.MissingCode -> MissingCode
          callback.EmptyCode -> EmptyCode
          callback.AmbiguousResponse -> AmbiguousCallback
          callback.InvalidParameterValue -> InvalidCallbackValue
        })
      })
  }
}

fn check_binding(
  client: Client,
  parsed: callback.Parsed,
  material: transactions.Material,
  browser: Option(BrowserBinding),
) -> Result(Nil, LoginError) {
  let #(state, issuer) = case parsed {
    callback.CodeResponse(state:, issuer:, ..)
    | callback.ErrorResponse(state:, issuer:, ..) -> #(state, issuer)
  }
  use _ <- result.try(case secure.constant_time_equal(state, material.state) {
    True -> Ok(Nil)
    False -> Error(CallbackRejected(UnknownState))
  })
  use binding <- result.try(case browser {
    Some(binding) -> Ok(binding)
    None -> Error(CallbackRejected(BrowserBindingMissing))
  })
  use _ <- result.try(
    case
      secure.constant_time_equal(
        secure.sha256_hex(redacted.reveal(binding.value)),
        material.browser_hash,
      )
    {
      True -> Ok(Nil)
      False -> Error(CallbackRejected(BrowserBindingMismatch))
    },
  )
  let configured_issuer = config.issuer(client.config)
  case issuer {
    Some(value) ->
      case value == configured_issuer {
        True -> Ok(Nil)
        False -> Error(CallbackRejected(CallbackIssuerMismatch))
      }
    None -> {
      let required = case config.issuer_parameter(client.config) {
        config.AlwaysRequireIssuer -> True
        config.RequireIssuerWhenAdvertised ->
          case native.metadata(client.backend) {
            Ok(metadata) -> metadata.issuer_parameter_supported
            // Without current metadata, require the parameter.
            Error(_) -> True
          }
      }
      case required {
        True -> Error(CallbackRejected(CallbackIssuerMissing))
        False -> Ok(Nil)
      }
    }
  }
}

fn denial(code: String) -> Denial {
  case code {
    "access_denied" -> AccessDenied
    "login_required" -> LoginRequired
    "consent_required" -> ConsentRequired
    "interaction_required" -> InteractionRequired
    "account_selection_required" -> AccountSelectionRequired
    "temporarily_unavailable" -> TemporarilyUnavailable
    "server_error" -> ServerError
    "invalid_request" -> InvalidRequestDenial
    "unauthorized_client" -> UnauthorizedClientDenial
    "unsupported_response_type" -> UnsupportedResponseType
    "invalid_scope" -> InvalidScopeDenial
    _ -> OtherDenial
  }
}

fn exchange(
  client: Client,
  material: transactions.Material,
  code: String,
) -> Result(LoginCompletion, LoginError) {
  let exchanged =
    native.exchange_code(
      client.backend,
      code:,
      redirect_uri: material.redirect_uri,
      nonce: material.nonce,
      verifier: material.verifier,
    )
  use response <- result.try(exchanged |> result.map_error(exchange_failure))
  use identity <- result.try(
    accept_identity(client, material, response)
    |> result.map_error(IdentityRejected),
  )
  install(client, identity, material, response)
}

fn exchange_failure(failure: protocol.Failure) -> LoginError {
  case failure {
    protocol.NotReady | protocol.Policy(_) ->
      ProviderUnavailableBeforeExchange(provider_failure(failure))
    protocol.Transport(sent: False, ..) ->
      ProviderUnavailableBeforeExchange(provider_failure(failure))
    protocol.Transport(sent: True, ..) -> ExchangeOutcomeUnknown
    protocol.Endpoint(status:, error:) if status == 400 || status == 401 ->
      case oauth_error(error) {
        NoOAuthError -> ExchangeOutcomeUnknown
        known -> ExchangeRejected(known)
      }
    protocol.Endpoint(..) -> ExchangeOutcomeUnknown
    protocol.Malformed -> ExchangeOutcomeUnknown
    protocol.IdTokenInvalid(reason:, claim:) ->
      IdentityRejected(identity_problem(reason, claim))
    protocol.UserinfoSubjectMismatch | protocol.Unmapped ->
      ExchangeOutcomeUnknown
  }
}

fn identity_problem(reason: String, claim: Option(String)) -> IdentityProblem {
  case reason {
    "subject_mismatch" -> SubjectMismatch
    "access_token_hash" -> AccessTokenHashMismatch
    "expired" -> IdTokenExpired
    "not_yet_valid" -> IdTokenNotYetValid
    "encrypted_unsigned" -> EncryptedUnsignedIdToken
    "encrypted_unsupported" -> EncryptedIdTokenUnsupported
    "alg_none" -> UnsignedIdToken
    "bad_signature" -> BadSignature
    "unknown_key" -> UnknownSigningKey
    "unsupported_algorithm" -> AlgorithmNotAllowed
    "malformed" -> MalformedIdToken
    "issuer_mismatch" -> IdTokenIssuerMismatch
    "audience_mismatch" -> IdTokenAudienceMismatch
    "authorized_party_mismatch" -> AuthorizedPartyMismatch
    "nonce_mismatch" -> NonceMismatch
    "missing_claim" -> MissingClaim(option.unwrap(claim, "other"))
    _ -> UnclassifiedIdentityFailure
  }
}

/// Warden's own binding checks on verified claims. The backend already
/// verified signature, issuer, audience, time, nonce and authorized party;
/// these checks bind the result to the consumed transaction and fail closed
/// if a backend did not.
fn accept_identity(
  client: Client,
  material: transactions.Material,
  response: protocol.TokenResponse,
) -> Result(VerifiedIdentity, IdentityProblem) {
  use id_token <- result.try(
    case response.id_token, response.id_token_malformed {
      Some(id_token), False -> Ok(id_token)
      _, True -> Error(MalformedIdToken)
      None, False -> Error(MissingIdToken)
    },
  )
  let claims = id_token.claims
  let issuer = config.issuer(client.config)
  let client_id = config.client_id(client.config)
  use _ <- result.try(case protocol.string_claim(claims, "iss") {
    Some(value) if value == issuer -> Ok(Nil)
    _ -> Error(IdTokenIssuerMismatch)
  })
  use _ <- result.try(case protocol.audiences(claims) {
    [audience] if audience == client_id -> Ok(Nil)
    _ -> Error(IdTokenAudienceMismatch)
  })
  use _ <- result.try(case protocol.string_claim(claims, "azp") {
    None -> Ok(Nil)
    Some(value) if value == client_id -> Ok(Nil)
    Some(_) -> Error(AuthorizedPartyMismatch)
  })
  use subject <- result.try(case protocol.string_claim(claims, "sub") {
    Some(subject) if subject != "" -> Ok(subject)
    _ -> Error(MissingClaim("sub"))
  })
  use _ <- result.try(case protocol.string_claim(claims, "nonce") {
    Some(nonce) ->
      case secure.constant_time_equal(nonce, material.nonce) {
        True -> Ok(Nil)
        False -> Error(NonceMismatch)
      }
    None -> Error(NonceMismatch)
  })
  use _ <- result.try(case material.max_age {
    None -> Ok(Nil)
    Some(max_age) ->
      case protocol.int_claim(claims, "auth_time") {
        Some(auth_time) if auth_time + max_age >= 0 ->
          case client.clock() - auth_time <= max_age {
            True -> Ok(Nil)
            False -> Error(AuthenticationTooOld)
          }
        _ -> Error(AuthenticationTooOld)
      }
  })
  use _ <- result.try(case response.access_token {
    Some(_) -> Ok(Nil)
    None -> Error(MalformedIdToken)
  })
  Ok(VerifiedIdentity(issuer:, subject:, claims: redacted.new(claims)))
}

// ===========================================================================
// Identity

/// A verified identity. Constructed only by this module after backend
/// verification and Warden's binding checks. The stable key is
/// `(issuer, subject)`; email is an optional claim, never a key.
pub opaque type VerifiedIdentity {
  VerifiedIdentity(issuer: String, subject: String, claims: Redacted(Dynamic))
}

pub type IdentityKey {
  IdentityKey(issuer: String, subject: String)
}

pub fn identity_key(identity: VerifiedIdentity) -> IdentityKey {
  IdentityKey(issuer: identity.issuer, subject: identity.subject)
}

pub fn issuer(identity: VerifiedIdentity) -> String {
  identity.issuer
}

pub fn subject(identity: VerifiedIdentity) -> String {
  identity.subject
}

pub fn email(identity: VerifiedIdentity) -> Option(String) {
  protocol.string_claim(redacted.reveal(identity.claims), "email")
}

pub fn email_verified(identity: VerifiedIdentity) -> Option(Bool) {
  decode.run(
    redacted.reveal(identity.claims),
    decode.at(["email_verified"], decode.bool),
  )
  |> option.from_result
}

pub fn name(identity: VerifiedIdentity) -> Option(String) {
  protocol.string_claim(redacted.reveal(identity.claims), "name")
}

pub fn preferred_username(identity: VerifiedIdentity) -> Option(String) {
  protocol.string_claim(redacted.reveal(identity.claims), "preferred_username")
}

/// `auth_time` in Unix seconds, when the provider included it.
pub fn authentication_time(identity: VerifiedIdentity) -> Option(Int) {
  protocol.int_claim(redacted.reveal(identity.claims), "auth_time")
}

pub fn acr(identity: VerifiedIdentity) -> Option(String) {
  protocol.string_claim(redacted.reveal(identity.claims), "acr")
}

pub fn amr(identity: VerifiedIdentity) -> List(String) {
  decode.run(
    redacted.reveal(identity.claims),
    decode.at(["amr"], decode.list(decode.string)),
  )
  |> result.unwrap([])
}

/// Decode verified ID-token claims into a caller-owned type.
pub fn decode_claims(
  identity: VerifiedIdentity,
  decoder: decode.Decoder(a),
) -> Result(a, List(decode.DecodeError)) {
  decode.run(redacted.reveal(identity.claims), decoder)
}

// ===========================================================================
// Sessions and custody

/// A session whose installation the custody owner confirmed. It carries the
/// verified identity and a custody reference and revision; tokens stay with
/// the custody owner.
pub opaque type Session {
  Session(
    identity: VerifiedIdentity,
    reference: Redacted(String),
    revision: Int,
    provider: String,
  )
}

pub fn session_identity(session: Session) -> VerifiedIdentity {
  session.identity
}

/// The custody reference, suitable for the application's own session store.
/// It is a random bearer value: keep it server-side or in an encrypted,
/// `HttpOnly` cookie.
pub fn session_reference(session: Session) -> String {
  redacted.reveal(session.reference)
}

pub fn session_revision(session: Session) -> Int {
  session.revision
}

/// Recovery for an installation whose outcome is unknown. It retains the
/// exact installation command, including token material; recovering never
/// exchanges the authorization code again.
pub opaque type CustodyRecovery {
  CustodyRecovery(
    provider: String,
    command: Redacted(custody.Install(VerifiedIdentity)),
  )
}

pub type CustodyRecoveryResult {
  CustodyRecovered(Session)
  CustodyStillUncertain(CustodyRecovery)
}

pub type CustodyRecoveryError {
  /// The recovery belongs to a different client configuration.
  RecoveryOwnerMismatch
  /// The custody owner returned a receipt for another command.
  ContradictoryReceipt
}

fn install(
  client: Client,
  identity: VerifiedIdentity,
  material: transactions.Material,
  response: protocol.TokenResponse,
) -> Result(LoginCompletion, LoginError) {
  let tokens =
    custody.Tokens(
      access_token: option.unwrap(response.access_token, ""),
      token_type: response.token_type,
      expires_at: option.map(response.expires_in, fn(s) { client.clock() + s }),
      refresh_token: response.refresh_token,
      id_token: option.map(response.id_token, fn(t) { t.token }),
      scopes: response.scopes,
    )
  let command =
    custody.Install(
      command_id: secure.random_token(24),
      provider: client.provider,
      identity:,
      evidence: custody.Evidence(
        nonce: material.nonce,
        auth_time: authentication_time(identity),
      ),
      tokens:,
    )
  let recovery =
    CustodyRecovery(provider: client.provider, command: redacted.new(command))
  case submit_install(client, recovery) {
    Ok(CustodyRecovered(session)) -> Ok(LoginCompleted(session))
    Ok(CustodyStillUncertain(recovery)) -> Ok(LoginRecoveryRequired(recovery))
    Error(_) -> Ok(LoginRecoveryRequired(recovery))
  }
}

fn submit_install(
  client: Client,
  recovery: CustodyRecovery,
) -> Result(CustodyRecoveryResult, CustodyRecoveryError) {
  let command = redacted.reveal(recovery.command)
  case custody.install(client.custody, command) {
    Error(_) -> Ok(CustodyStillUncertain(recovery))
    Ok(receipt) if receipt.command_id == command.command_id ->
      Ok(
        CustodyRecovered(Session(
          identity: command.identity,
          reference: redacted.new(receipt.reference),
          revision: receipt.revision,
          provider: client.provider,
        )),
      )
    Ok(_) -> Error(ContradictoryReceipt)
  }
}

/// Resubmit an installation whose outcome was unknown. The custody owner
/// returns the original receipt if it already accepted the command.
pub fn recover_custody(
  client: Client,
  recovery: CustodyRecovery,
) -> Result(CustodyRecoveryResult, CustodyRecoveryError) {
  case recovery.provider == client.provider {
    False -> Error(RecoveryOwnerMismatch)
    True -> submit_install(client, recovery)
  }
}

pub type SessionError {
  /// The custody owner has no such session (unknown, logged out, or lost on
  /// restart of the in-memory owner).
  SessionNotFound
  /// The session belongs to another client configuration.
  SessionForeign
  /// A newer revision exists; restore the session again.
  SessionStale
  SessionStoreUnavailable
  /// The session has no access token material.
  SessionHasNoAccessToken
}

/// Load a session from its custody reference, e.g. from the application's
/// session cookie.
pub fn restore_session(
  client: Client,
  reference: String,
) -> Result(Session, SessionError) {
  use snapshot <- result.try(load(client, reference))
  Ok(Session(
    identity: snapshot.identity,
    reference: redacted.new(snapshot.reference),
    revision: snapshot.revision,
    provider: snapshot.provider,
  ))
}

fn load(
  client: Client,
  reference: String,
) -> Result(custody.Snapshot(VerifiedIdentity), SessionError) {
  case custody.get(client.custody, reference) {
    Error(_) -> Error(SessionStoreUnavailable)
    Ok(Error(Nil)) -> Error(SessionNotFound)
    Ok(Ok(snapshot)) if snapshot.provider != client.provider ->
      Error(SessionForeign)
    Ok(Ok(snapshot)) -> Ok(snapshot)
  }
}

fn load_current(
  client: Client,
  session: Session,
) -> Result(custody.Snapshot(VerifiedIdentity), SessionError) {
  use _ <- result.try(case session.provider == client.provider {
    True -> Ok(Nil)
    False -> Error(SessionForeign)
  })
  use snapshot <- result.try(load(client, redacted.reveal(session.reference)))
  case snapshot.revision == session.revision {
    True -> Ok(snapshot)
    False -> Error(SessionStale)
  }
}

/// An access token. `string.inspect` shows no token value.
pub opaque type AccessToken {
  AccessToken(reveal: fn() -> String, token_type: String)
}

/// The token value for constructing a resource request. Treat it as a
/// secret: do not log or persist it.
pub fn access_token_value(token: AccessToken) -> String {
  token.reveal()
}

pub fn access_token_type(token: AccessToken) -> String {
  token.token_type
}

/// An `Authorization` header for a resource request.
pub fn authorization_header(token: AccessToken) -> #(String, String) {
  #("authorization", "Bearer " <> token.reveal())
}

fn access_token(value: String, token_type: String) -> AccessToken {
  AccessToken(reveal: fn() { value }, token_type:)
}

/// The session's current access token, read from custody at the session's
/// revision, with its expiry (Unix seconds) when the provider stated one.
pub fn session_access_token(
  client: Client,
  session: Session,
) -> Result(#(AccessToken, Option(Int)), SessionError) {
  use snapshot <- result.try(load_current(client, session))
  case snapshot.tokens.access_token {
    "" -> Error(SessionHasNoAccessToken)
    value ->
      Ok(#(
        access_token(value, snapshot.tokens.token_type),
        snapshot.tokens.expires_at,
      ))
  }
}

/// Scopes granted to the session's current access token.
pub fn session_scopes(
  client: Client,
  session: Session,
) -> Result(List(String), SessionError) {
  load_current(client, session)
  |> result.map(fn(s) { s.tokens.scopes })
}

// ===========================================================================
// Refresh

pub type RefreshResult {
  /// New access material was published; use the returned session.
  RefreshCompleted(Session)
  /// Proven not sent; the generation was released for a later attempt.
  RefreshDidNotSend(ProviderFailure)
  /// The token endpoint rejected the refresh. After `invalid_grant` the
  /// refresh token is revoked in custody; reauthenticate.
  RefreshRejectedByEndpoint(OAuthError)
  /// The request may have reached the provider, which may have rotated the
  /// refresh token. The generation is quarantined; reauthenticate.
  RefreshProviderQuarantined(RefreshReservationRecovery)
  /// The provider answered but the response was not acceptable. It may have
  /// rotated the refresh token, so the generation is quarantined.
  RefreshResponseQuarantined(RefreshValidationError, RefreshReservationRecovery)
  /// The custody owner did not confirm reservation or settlement.
  RefreshReservationUnresolved(RefreshReservationRecovery)
  /// New material was submitted for publication but not acknowledged. Call
  /// `recover_refresh_publication`; the provider is not called again.
  RefreshPublicationUnresolved(RefreshPublicationRecovery)
}

pub type RefreshValidationError {
  /// The refreshed ID token names a different subject.
  RefreshedSubjectMismatch
  RefreshedIssuerMismatch
  RefreshedAudienceMismatch
  RefreshedAuthorizedPartyMismatch
  RefreshedNonceMismatch
  RefreshedAuthenticationTimeMismatch
  RefreshedScopeChangeUnsupported
  RefreshedIdTokenInvalid(IdentityProblem)
  RefreshResponseMalformed
}

pub type RefreshError {
  RefreshSessionForeign
  RefreshSessionMissing
  /// The session revision is older than custody's; restore and retry.
  RefreshSessionStale
  /// Another refresh of this generation is outstanding.
  RefreshInProgress
  /// The generation is quarantined after an uncertain refresh.
  RefreshQuarantined
  /// The session has no refresh token.
  RefreshTokenUnavailable
  /// A previous refresh was rejected with `invalid_grant`.
  RefreshRevoked
  RefreshStoreUnavailable
  /// The custody owner refused the publication (for example after losing
  /// the reservation on restart). The refreshed material is discarded.
  RefreshPublicationRejected
  RecoveryForeign
}

/// Reservation-phase recovery evidence. It identifies the quarantined or
/// unresolved generation; it cannot authorise another provider call.
pub opaque type RefreshReservationRecovery {
  RefreshReservationRecovery(
    provider: String,
    reference: Redacted(String),
    command_id: String,
  )
}

pub fn reservation_recovery_reference(
  recovery: RefreshReservationRecovery,
) -> String {
  redacted.reveal(recovery.reference)
}

/// Publication-phase recovery: the exact publication command.
pub opaque type RefreshPublicationRecovery {
  RefreshPublicationRecovery(
    provider: String,
    command: Redacted(custody.Publish),
    identity: VerifiedIdentity,
  )
}

/// Refresh the session's access material. At most one refresh per session
/// generation is outstanding; a possibly transmitted refresh token is never
/// sent again.
pub fn refresh_session(
  client: Client,
  session: Session,
) -> Result(RefreshResult, RefreshError) {
  use _ <- result.try(case session.provider == client.provider {
    True -> Ok(Nil)
    False -> Error(RefreshSessionForeign)
  })
  let command_id = secure.random_token(24)
  let recovery =
    RefreshReservationRecovery(
      provider: client.provider,
      reference: session.reference,
      command_id:,
    )
  case
    custody.reserve_refresh(
      client.custody,
      redacted.reveal(session.reference),
      client.provider,
      session.revision,
      command_id,
    )
  {
    Error(_) -> Ok(RefreshReservationUnresolved(recovery))
    Ok(custody.ReservationMissing) -> Error(RefreshSessionMissing)
    Ok(custody.ReservationStale) -> Error(RefreshSessionStale)
    Ok(custody.ReservationBusy) -> Error(RefreshInProgress)
    Ok(custody.ReservationQuarantined) -> Error(RefreshQuarantined)
    Ok(custody.ReservationNoRefreshToken) -> Error(RefreshTokenUnavailable)
    Ok(custody.ReservationRevoked) -> Error(RefreshRevoked)
    Ok(custody.ReservationProviderMismatch) -> Error(RefreshSessionForeign)
    Ok(custody.Reserved(dispatch)) ->
      Ok(dispatch_refresh(client, session, dispatch, recovery))
  }
}

fn dispatch_refresh(
  client: Client,
  session: Session,
  dispatch: custody.Dispatch(VerifiedIdentity),
  recovery: RefreshReservationRecovery,
) -> RefreshResult {
  let outcome =
    native.refresh(client.backend, refresh_token: dispatch.refresh_token)
  let settle = fn(settlement, result) {
    case
      custody.settle_refresh(
        client.custody,
        dispatch.reference,
        dispatch.dispatch_id,
        settlement,
      )
    {
      Ok(custody.Settled) -> result
      _ -> RefreshReservationUnresolved(recovery)
    }
  }
  case outcome {
    Error(failure) ->
      case failure {
        protocol.NotReady
        | protocol.Policy(_)
        | protocol.Transport(sent: False, ..) ->
          settle(
            custody.SettleNotSent,
            RefreshDidNotSend(provider_failure(failure)),
          )
        protocol.Endpoint(status:, error:) if status == 400 || status == 401 ->
          case oauth_error(error) {
            InvalidGrant ->
              settle(
                custody.SettleRejected,
                RefreshRejectedByEndpoint(InvalidGrant),
              )
            NoOAuthError ->
              settle(
                custody.SettleQuarantine,
                RefreshProviderQuarantined(recovery),
              )
            other ->
              settle(custody.SettleNotSent, RefreshRejectedByEndpoint(other))
          }
        protocol.IdTokenInvalid(reason:, claim:) ->
          settle(
            custody.SettleQuarantine,
            RefreshResponseQuarantined(
              RefreshedIdTokenInvalid(identity_problem(reason, claim)),
              recovery,
            ),
          )
        protocol.Malformed ->
          settle(
            custody.SettleQuarantine,
            RefreshResponseQuarantined(RefreshResponseMalformed, recovery),
          )
        protocol.Transport(sent: True, ..)
        | protocol.Endpoint(..)
        | protocol.UserinfoSubjectMismatch
        | protocol.Unmapped ->
          settle(custody.SettleQuarantine, RefreshProviderQuarantined(recovery))
      }
    Ok(response) ->
      case refreshed_update(client, dispatch, response) {
        Error(problem) ->
          settle(
            custody.SettleQuarantine,
            RefreshResponseQuarantined(problem, recovery),
          )
        Ok(update) -> {
          let command =
            custody.Publish(
              reference: dispatch.reference,
              dispatch_id: dispatch.dispatch_id,
              command_id: dispatch.command_id,
              update:,
            )
          publish(
            client,
            RefreshPublicationRecovery(
              provider: client.provider,
              command: redacted.new(command),
              identity: session.identity,
            ),
          )
          |> result.unwrap(RefreshReservationUnresolved(recovery))
        }
      }
  }
}

/// Continuity of the refreshed ID token with the original authentication
/// (OIDC Core §12.2) and the unchanged-scope profile.
fn refreshed_update(
  client: Client,
  dispatch: custody.Dispatch(VerifiedIdentity),
  response: protocol.TokenResponse,
) -> Result(custody.Update, RefreshValidationError) {
  use access <- result.try(case response.access_token {
    Some(token) -> Ok(token)
    None -> Error(RefreshResponseMalformed)
  })
  use _ <- result.try(case response.id_token_malformed {
    True -> Error(RefreshResponseMalformed)
    False -> Ok(Nil)
  })
  use id_token <- result.try(case response.id_token {
    Some(id_token) -> {
      let claims = id_token.claims
      let original = dispatch.identity
      let client_id = config.client_id(client.config)
      use _ <- result.try(case protocol.string_claim(claims, "iss") {
        Some(value) if value == original.issuer -> Ok(Nil)
        _ -> Error(RefreshedIssuerMismatch)
      })
      use _ <- result.try(case protocol.string_claim(claims, "sub") {
        Some(value) if value == original.subject -> Ok(Nil)
        _ -> Error(RefreshedSubjectMismatch)
      })
      use _ <- result.try(
        case protocol.audiences(claims) == [config.client_id(client.config)] {
          True -> Ok(Nil)
          False -> Error(RefreshedAudienceMismatch)
        },
      )
      use _ <- result.try(case protocol.string_claim(claims, "azp") {
        None -> Ok(Nil)
        Some(value) if value == client_id -> Ok(Nil)
        Some(_) -> Error(RefreshedAuthorizedPartyMismatch)
      })
      use _ <- result.try(case protocol.string_claim(claims, "nonce") {
        None -> Ok(Nil)
        Some(nonce) ->
          case secure.constant_time_equal(nonce, dispatch.evidence.nonce) {
            True -> Ok(Nil)
            False -> Error(RefreshedNonceMismatch)
          }
      })
      use _ <- result.try(
        case
          protocol.int_claim(claims, "auth_time"),
          dispatch.evidence.auth_time
        {
          Some(new), Some(old) if new != old ->
            Error(RefreshedAuthenticationTimeMismatch)
          _, _ -> Ok(Nil)
        },
      )
      Ok(custody.ReplaceWith(id_token.token))
    }
    // OIDC Core §12.2: a refresh response may omit the ID token; the
    // established identity and logout hint are retained.
    None -> Ok(custody.Retain)
  })
  use scopes <- result.try(case response.scopes {
    [] -> Ok(custody.Retain)
    scopes ->
      case set.from_list(scopes) == set.from_list(dispatch.scopes) {
        True -> Ok(custody.ReplaceWith(scopes))
        False -> Error(RefreshedScopeChangeUnsupported)
      }
  })
  Ok(custody.Update(
    access_token: access,
    token_type: response.token_type,
    expires_at: option.map(response.expires_in, fn(s) { client.clock() + s }),
    refresh_token: case response.refresh_token {
      Some(token) -> custody.ReplaceWith(token)
      None -> custody.Retain
    },
    id_token:,
    scopes:,
  ))
}

fn publish(
  client: Client,
  recovery: RefreshPublicationRecovery,
) -> Result(RefreshResult, RefreshError) {
  let command = redacted.reveal(recovery.command)
  case custody.publish_refresh(client.custody, command) {
    Error(_) -> Ok(RefreshPublicationUnresolved(recovery))
    Ok(custody.PublishRejected) -> Error(RefreshPublicationRejected)
    Ok(custody.Published(receipt)) ->
      case
        receipt.command_id == command.command_id
        && receipt.reference == command.reference
      {
        True ->
          Ok(
            RefreshCompleted(Session(
              identity: recovery.identity,
              reference: redacted.new(receipt.reference),
              revision: receipt.revision,
              provider: client.provider,
            )),
          )
        False -> Ok(RefreshPublicationUnresolved(recovery))
      }
  }
}

/// Resubmit an unacknowledged publication. The provider is not called; the
/// custody owner returns the original receipt if it already accepted it.
pub fn recover_refresh_publication(
  client: Client,
  recovery: RefreshPublicationRecovery,
) -> Result(RefreshResult, RefreshError) {
  case recovery.provider == client.provider {
    False -> Error(RecoveryForeign)
    True -> publish(client, recovery)
  }
}

// ===========================================================================
// Userinfo

/// Userinfo claims whose `sub` equals the session's subject.
pub opaque type UserInfo {
  UserInfo(subject: String, claims: Dynamic)
}

pub fn userinfo_subject(info: UserInfo) -> String {
  info.subject
}

pub fn decode_userinfo(
  info: UserInfo,
  decoder: decode.Decoder(a),
) -> Result(a, List(decode.DecodeError)) {
  decode.run(info.claims, decoder)
}

pub type UserinfoError {
  UserinfoSession(SessionError)
  UserinfoNotSupported
  /// The response `sub` differs from the session's subject.
  UserinfoSubjectMismatch
  UserinfoFailed(ProviderFailure)
}

pub fn userinfo(
  client: Client,
  session: Session,
) -> Result(UserInfo, UserinfoError) {
  use snapshot <- result.try(
    load_current(client, session) |> result.map_error(UserinfoSession),
  )
  use metadata <- result.try(
    native.metadata(client.backend)
    |> result.map_error(fn(f) { UserinfoFailed(provider_failure(f)) }),
  )
  use _ <- result.try(case metadata.userinfo_endpoint {
    Some(_) -> Ok(Nil)
    None -> Error(UserinfoNotSupported)
  })
  let subject = snapshot.identity.subject
  case
    native.userinfo(
      client.backend,
      access_token: snapshot.tokens.access_token,
      expected_subject: subject,
    )
  {
    Ok(claims) ->
      case protocol.string_claim(claims, "sub") {
        Some(value) if value == subject -> Ok(UserInfo(subject:, claims:))
        _ -> Error(UserinfoSubjectMismatch)
      }
    Error(protocol.UserinfoSubjectMismatch) -> Error(UserinfoSubjectMismatch)
    Error(failure) -> Error(UserinfoFailed(provider_failure(failure)))
  }
}

// ===========================================================================
// Client credentials

pub type ClientToken {
  ClientToken(
    access_token: AccessToken,
    /// Lifetime in seconds as stated by the provider; not fabricated.
    expires_in: Option(Int),
    scopes: List(String),
  )
}

pub type ClientCredentialsError {
  /// Public clients cannot use the client credentials grant.
  ClientCredentialsNeedConfidentialClient
  ClientCredentialsInvalidScope(String)
  ClientCredentialsNotSent(ProviderFailure)
  ClientCredentialsRejected(OAuthError)
  /// The request may have reached the provider; its outcome is unknown.
  ClientCredentialsOutcomeUnknown
}

/// Obtain an access token for the client itself. Independent of any login
/// identity. Tokens are returned to the caller, not stored.
pub fn client_credentials(
  client: Client,
  scopes: List(String),
) -> Result(ClientToken, ClientCredentialsError) {
  use _ <- result.try(case config.authentication_method(client.config) {
    "none" -> Error(ClientCredentialsNeedConfidentialClient)
    _ -> Ok(Nil)
  })
  use _ <- result.try(
    list.try_each(scopes, fn(scope) {
      case config.valid_scope(scope) {
        True -> Ok(Nil)
        False -> Error(ClientCredentialsInvalidScope(scope))
      }
    }),
  )
  case native.client_credentials(client.backend, scopes) {
    Ok(protocol.TokenResponse(access_token: Some(token), ..) as response) ->
      Ok(ClientToken(
        access_token: access_token(token, response.token_type),
        expires_in: response.expires_in,
        scopes: response.scopes,
      ))
    Ok(_) -> Error(ClientCredentialsOutcomeUnknown)
    Error(failure) ->
      Error(case failure {
        protocol.NotReady
        | protocol.Policy(_)
        | protocol.Transport(sent: False, ..) ->
          ClientCredentialsNotSent(provider_failure(failure))
        protocol.Endpoint(status:, error:) if status == 400 || status == 401 ->
          case oauth_error(error) {
            NoOAuthError -> ClientCredentialsOutcomeUnknown
            known -> ClientCredentialsRejected(known)
          }
        _ -> ClientCredentialsOutcomeUnknown
      })
  }
}

// ===========================================================================
// Introspection

pub type Introspection {
  /// The provider reports the token active. Introspection does not itself
  /// authorise a resource request or establish a login.
  ActiveToken(TokenInfo)
  InactiveToken
}

pub type TokenInfo {
  TokenInfo(
    client_id: Option(String),
    subject: Option(String),
    username: Option(String),
    scopes: List(String),
    expires_at: Option(Int),
    issued_at: Option(Int),
    token_type: Option(String),
    issuer: Option(String),
    claims: Dynamic,
  )
}

pub type IntrospectionError {
  IntrospectionNotSupported
  IntrospectionFailed(ProviderFailure)
}

pub fn introspect(
  client: Client,
  token: String,
) -> Result(Introspection, IntrospectionError) {
  case native.introspect(client.backend, token) {
    Ok(protocol.Inactive) -> Ok(InactiveToken)
    Ok(protocol.Active(..) as a) ->
      Ok(
        ActiveToken(TokenInfo(
          client_id: a.client_id,
          subject: a.subject,
          username: a.username,
          scopes: a.scopes,
          expires_at: a.expires_at,
          issued_at: a.issued_at,
          token_type: a.token_type,
          issuer: a.issuer,
          claims: a.extra,
        )),
      )
    Error(protocol.Policy("endpoint_missing")) ->
      Error(IntrospectionNotSupported)
    Error(failure) -> Error(IntrospectionFailed(provider_failure(failure)))
  }
}

// ===========================================================================
// Logout

pub type LogoutOptions {
  LogoutOptions(
    /// Must be registered with the provider; validated like redirect URIs.
    post_logout_redirect_uri: Option(String),
    state: Option(String),
  )
}

pub type LogoutOutcome {
  /// Local custody was removed; redirect the browser here to end the
  /// provider session (RP-Initiated Logout).
  RedirectToProvider(url: String)
  /// Local custody was removed; the provider has no end-session endpoint.
  NoEndSessionEndpoint
}

pub type LogoutError {
  LogoutSession(SessionError)
  InvalidPostLogoutRedirect
  InvalidLogoutState
  /// Custody removal was not confirmed; the session may still exist.
  LogoutStoreUnavailable
  LogoutProviderUnavailable(ProviderFailure)
}

/// End the session: remove its custody first, then build the provider
/// logout URL with the logout-only ID-token hint.
pub fn logout(
  client: Client,
  session: Session,
  options: LogoutOptions,
) -> Result(LogoutOutcome, LogoutError) {
  use _ <- result.try(case options.post_logout_redirect_uri {
    Some(uri) ->
      case config.valid_redirect_uri(uri) {
        True -> Ok(Nil)
        False -> Error(InvalidPostLogoutRedirect)
      }
    None -> Ok(Nil)
  })
  use _ <- result.try(case options.state {
    Some(state) ->
      case state != "" && printable(state) {
        True -> Ok(Nil)
        False -> Error(InvalidLogoutState)
      }
    None -> Ok(Nil)
  })
  use snapshot <- result.try(
    load_current(client, session) |> result.map_error(LogoutSession),
  )
  use _ <- result.try(
    custody.remove(client.custody, redacted.reveal(session.reference))
    |> result.replace_error(LogoutStoreUnavailable),
  )
  use metadata <- result.try(
    native.metadata(client.backend)
    |> result.map_error(fn(f) { LogoutProviderUnavailable(provider_failure(f)) }),
  )
  case metadata.end_session_endpoint {
    None -> Ok(NoEndSessionEndpoint)
    Some(_) ->
      native.logout_url(
        client.backend,
        id_token_hint: snapshot.tokens.id_token,
        post_logout_redirect_uri: options.post_logout_redirect_uri,
        state: options.state,
      )
      |> result.map(RedirectToProvider)
      |> result.map_error(fn(f) {
        LogoutProviderUnavailable(provider_failure(f))
      })
  }
}

// ===========================================================================
// Shared helpers

fn provider_failure(failure: protocol.Failure) -> ProviderFailure {
  case failure {
    protocol.NotReady -> ProviderNotReady
    protocol.Transport(sent:, class:) ->
      TransportFailure(sent:, reason: transport_reason(class))
    protocol.Endpoint(status:, error:) ->
      ProviderStatus(status:, error: oauth_error(error))
    protocol.Malformed -> MalformedProviderResponse
    protocol.Policy("issuer_mismatch") -> IssuerMismatch
    protocol.Policy(_)
    | protocol.IdTokenInvalid(..)
    | protocol.UserinfoSubjectMismatch
    | protocol.Unmapped -> UnclassifiedBackendFailure
  }
}

fn transport_reason(class: String) -> TransportReason {
  case class {
    "destination_rejected" -> DestinationRejected
    "insecure_scheme" -> InsecureScheme
    "invalid_destination" -> InvalidDestination
    "resolution_failed" -> ResolutionFailed
    "connection_refused" -> ConnectionRefused
    "connection_failed" -> ConnectionFailed
    "tls_rejected" -> TlsRejected
    "timeout" -> Timeout
    "body_too_large" -> ResponseTooLarge
    "headers_too_large" -> ResponseHeadersTooLarge
    "malformed_response" -> MalformedHttp
    "truncated_body" -> TruncatedResponse
    "unsupported_content_encoding" -> UnsupportedContentEncoding
    _ -> OtherTransportFailure
  }
}

fn oauth_error(code: String) -> OAuthError {
  case code {
    "invalid_request" -> InvalidRequest
    "invalid_client" -> InvalidClient
    "invalid_grant" -> InvalidGrant
    "unauthorized_client" -> UnauthorizedClient
    "unsupported_grant_type" -> UnsupportedGrantType
    "invalid_scope" -> InvalidScope
    "invalid_token" -> InvalidToken
    "insufficient_scope" -> InsufficientScope
    "none" -> NoOAuthError
    _ -> OtherOAuthError
  }
}

// ===========================================================================
// Test support (internal)

@internal
pub fn transaction_store(client: Client) -> transactions.Store {
  client.transactions
}

@internal
pub fn custody_owner(client: Client) -> custody.Store(VerifiedIdentity) {
  client.custody
}

/// Registered name of the provider cache process.
@internal
pub fn provider_worker(client: Client) -> Dynamic {
  client.provider_name
}

@internal
pub fn supervisor_pid(client: Client) -> Pid {
  client.supervisor
}

@internal
pub fn call_error_is_timeout(error: call.CallError) -> Bool {
  error == call.CallTimedOut
}
