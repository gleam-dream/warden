//// Warden: a typed OpenID Connect relying party and OAuth client.
////
//// This module is the canonical owner of verified identity and sessions. A
//// `VerifiedIdentity` exists only after Warden verified an ID token for a
//// login transaction it consumed atomically, and compared the verified
//// issuer, audience, authorized party, subject and nonce with that
//// transaction. A `Session` exists only after custody confirmed the
//// installation of that identity and its tokens.
////
//// ```gleam
//// let assert Ok(client) = warden.new(config)
//// let assert Ok(Nil) = warden.start(client)   // or warden.supervised(client)
////
//// // GET /login
//// let assert Ok(redirect) = warden.begin_login(client, request, warden.default_login())
//// warden.login_response(response.new(303), redirect)   // Location, binding cookie
////
//// // GET or POST /auth/callback
//// case warden.complete_login(client, request) {
////   Ok(session) -> warden.session_reference(session)    // keep in the app's session
////   Error(error) -> warden.login_error_action(error)    // Reauthenticate, RejectRequest, ...
//// }
////
//// // Any later request
//// use session <- result.try(warden.restore_session(client, reference))
//// use access <- result.map(warden.access_token(client, session))
//// warden.authorize(api_request, access.token)
//// ```
////
//// Error unions may gain variants. Branch on the `Action` that
//// `login_error_action` and `session_error_action` return, and log with the
//// `describe_*` functions.

import gleam/bit_array
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/http
import gleam/http/cookie
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/otp/actor
import gleam/otp/static_supervisor as supervisor
import gleam/otp/supervision
import gleam/result
import gleam/set
import gleam/string
import gleam/time/duration.{type Duration}
import gleam/time/timestamp.{type Timestamp}
import gleam/uri
import sinal
import sinal/correlation.{type Correlation}
import warden/config.{type Config, type ConfigError}
import warden/internal/callback
import warden/internal/custody
import warden/internal/logins
import warden/internal/memory_store
import warden/internal/native/client as native
import warden/internal/native/provider
import warden/internal/port
import warden/internal/protocol
import warden/internal/redacted.{type Redacted}
import warden/internal/runtime
import warden/internal/sealed
import warden/internal/secure
import warden/internal/settings.{type Settings}
import warden/internal/sweeper
import warden/internal/transport
import warden/telemetry

// ===========================================================================
// Client lifecycle

/// A Warden client. `new` validates the configuration and allocates the
/// names of the client's processes once, so the value stays valid when a
/// supervisor restarts them.
pub type Client =
  runtime.Client

/// Why a client did not start. May gain variants.
pub type StartError {
  /// The configuration is invalid (`config.describe_config_error`).
  InvalidConfig(List(ConfigError))
  /// Discovery through Warden's transport failed.
  DiscoveryFailed(ProviderFailure)
  /// The provider's metadata is incompatible with Warden's policy.
  ProviderIncompatible(List(Incompatibility))
  /// Metadata or keys did not load within the startup timeout.
  StartupTimedOut
  /// The client's processes are already running.
  AlreadyStarted
  /// A Warden process failed to start.
  ProcessStartFailed
}

/// A provider capability Warden's policy requires. May gain variants (PAR,
/// JAR support).
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
  /// The provider requires pushed authorization requests.
  RequiresPushedAuthorization
  /// The provider requires signed request objects.
  RequiresRequestObjects
  /// The authorization endpoint is not an absolute `https` URI.
  InsecureAuthorizationEndpoint
  /// The end-session endpoint is not an absolute `https` URI.
  InsecureEndSessionEndpoint
  MissingTokenEndpoint
}

/// Validate a configuration and prepare a client. Starts nothing.
pub fn new(config: Config) -> Result(Client, StartError) {
  use _ <- result.try(
    config.validate(config) |> result.map_error(InvalidConfig),
  )
  let names =
    runtime.Names(
      supervisor: process.new_name("warden"),
      provider: process.new_name("warden_provider"),
      sweeper: process.new_name("warden_sweeper"),
      memory_custody: case config.custody_store {
        Some(_) -> None
        None -> Some(process.new_name("warden_custody"))
      },
      memory_logins: case config.transaction_store {
        Some(_) -> None
        None -> Some(process.new_name("warden_logins"))
      },
      pool: transport.new_pool(),
    )
  let keys = case config.sealing_key {
    Some(key) -> sealed.keys(key, config.previous_sealing_keys)
    None -> sealed.ephemeral()
  }
  let timeout = config.store_timeout_ms
  let custody_port = case config.custody_store, names.memory_custody {
    Some(store), _ -> port.Port(store:, timeout_ms: timeout)
    None, Some(name) ->
      port.Port(
        store: memory_store.store(process.named_subject(name), timeout),
        timeout_ms: timeout,
      )
    None, None -> panic as "warden.new: no custody store"
  }
  let logins_port = case config.transaction_store, names.memory_logins {
    Some(store), _ -> port.Port(store:, timeout_ms: timeout)
    None, Some(name) ->
      port.Port(
        store: memory_store.store(process.named_subject(name), timeout),
        timeout_ms: timeout,
      )
    None, None -> panic as "warden.new: no login store"
  }
  let http =
    transport.Policy(..transport_policy(config), pool: Some(names.pool))
  let provider_handle =
    provider.Provider(
      process.named_subject(names.provider),
      // R11: a key refetch takes up to one request timeout.
      config.request_timeout_ms + 1000,
    )
  Ok(runtime.Client(
    settings: config,
    provider: config.issuer <> " " <> config.client_id,
    names:,
    backend: native.new(config, provider_handle, http),
    custody: custody.Custody(
      port: custody_port,
      keys:,
      clock: config.clock,
      absolute: config.session_absolute_seconds,
      idle: config.session_idle_seconds,
      retention: config.login_lifetime_seconds,
      epoch: option.map(names.memory_custody, fn(name) {
        fn() { memory_store.epoch(process.named_subject(name), timeout) }
      }),
    ),
    logins: logins.Logins(
      port: logins_port,
      keys:,
      clock: config.clock,
      retention: config.login_lifetime_seconds,
    ),
    http:,
    correlation: None,
  ))
}

/// Start the client's processes under a supervisor linked to the caller,
/// after discovering the provider and checking its metadata. Waits at most
/// the startup timeout (default 15 s).
pub fn start(client: Client) -> Result(Nil, StartError) {
  use _ <- result.try(ensure_applications())
  use _ <- result.try(case process.named(client.names.supervisor) {
    Ok(_) -> Error(AlreadyStarted)
    Error(Nil) -> Ok(Nil)
  })
  let settings = client.settings
  // One discovery and key load within the startup timeout, on a one-shot
  // HTTP Gun client; the provider cache starts from it.
  let deadline = secure.monotonic_ms() + settings.startup_timeout_ms
  let one_shot = transport.Policy(..client.http, pool: None)
  use discovered <- result.try(
    provider.discover(settings.issuer, one_shot, deadline)
    |> result.map_error(fn(f) {
      case secure.monotonic_ms() >= deadline {
        True -> StartupTimedOut
        False -> DiscoveryFailed(provider_failure(f))
      }
    }),
  )
  use _ <- result.try(case compatibility(settings, discovered.metadata) {
    [] -> Ok(Nil)
    problems -> Error(ProviderIncompatible(problems))
  })
  start_tree(client, Some(discovered)) |> result.replace(Nil)
}

/// A child specification for an application supervision tree. The child
/// starts at once and discovers the provider in the background, retrying
/// with backoff from 1 s to 60 s; until discovery succeeds and the metadata
/// is compatible, operations fail with `ProviderNotReady`. A restart keeps
/// the same names, so `client` stays valid.
pub fn supervised(client: Client) -> supervision.ChildSpecification(Client) {
  supervision.supervisor(fn() {
    case
      ensure_applications() |> result.try(fn(_) { start_tree(client, None) })
    {
      Ok(pid) -> Ok(actor.Started(pid:, data: client))
      Error(error) -> Error(actor.InitFailed(describe_start_error(error)))
    }
  })
}

/// Stop the client's processes. Returns once its supervisor has exited (at
/// most five seconds), so a request started afterwards fails as not sent.
/// A client started with `supervised` belongs to its parent supervisor:
/// stop it there, or the parent restarts it.
pub fn stop(client: Client) -> Nil {
  case process.named(client.names.supervisor) {
    Error(Nil) -> Nil
    Ok(pid) -> {
      let monitor = process.monitor(pid)
      process.unlink(pid)
      process.send_abnormal_exit(pid, Shutdown)
      let _ =
        process.new_selector()
        |> process.select_specific_monitor(monitor, fn(_) { Nil })
        |> process.selector_receive(5000)
      Nil
    }
  }
}

type ExitReason {
  Shutdown
}

/// A view of the client whose events and provider requests carry
/// `correlation` (`warden/telemetry`, HTTP Gun's events). Pure: the
/// underlying processes are shared.
pub fn with_correlation(client: Client, correlation: Correlation) -> Client {
  let http = transport.Policy(..client.http, correlation: Some(correlation))
  runtime.Client(
    ..client,
    correlation: Some(correlation),
    http:,
    backend: native.with_policy(client.backend, http),
  )
}

fn ensure_applications() -> Result(Nil, StartError) {
  case secure.ensure_applications() {
    True -> Ok(Nil)
    False -> Error(ProcessStartFailed)
  }
}

fn start_tree(
  client: Client,
  seed: Option(provider.Discovered),
) -> Result(process.Pid, StartError) {
  let settings = client.settings
  let names = client.names
  let accept = fn(metadata) { compatibility(settings, metadata) == [] }
  let memory = fn(builder, name, capacity) {
    case name {
      None -> builder
      Some(name) ->
        supervisor.add(
          builder,
          supervision.worker(fn() {
            memory_store.start(name, capacity, settings.clock)
          }),
        )
    }
  }
  let builder =
    supervisor.new(supervisor.OneForOne)
    |> supervisor.restart_tolerance(intensity: 10, period: 60)
    |> supervisor.add(transport.pool_child(client.http, names.pool))
    |> supervisor.add(
      supervision.worker(fn() {
        provider.start(
          names.provider,
          settings.issuer,
          client.http,
          seed,
          accept,
        )
      }),
    )
  let builder =
    builder
    |> memory(names.memory_logins, Some(settings.max_pending_logins))
    |> memory(names.memory_custody, None)
    |> supervisor.add(
      supervision.worker(fn() {
        sweeper.start(
          names.sweeper,
          [client.custody.port, client.logins.port],
          settings.clock,
        )
      }),
    )
  case supervisor.start(builder) {
    Error(_) -> Error(ProcessStartFailed)
    Ok(actor.Started(pid:, ..)) ->
      case process.register(pid, names.supervisor) {
        Ok(Nil) -> Ok(pid)
        Error(Nil) -> {
          process.unlink(pid)
          process.kill(pid)
          Error(AlreadyStarted)
        }
      }
  }
}

fn transport_policy(settings: Settings) -> transport.Policy {
  let #(allow_loopback, allow_private) = case settings.destinations {
    settings.PublicOnly -> #(False, False)
    settings.AllowLoopback -> #(True, False)
    settings.AllowPrivate -> #(False, True)
  }
  transport.Policy(
    ..transport.policy(case settings.trust {
      settings.Anchors(ders) -> transport.Anchors(ders)
      _ -> transport.SystemTrust
    }),
    allow_loopback:,
    allow_private:,
    allowed_hosts: settings.allowed_hosts,
    timeout_ms: settings.request_timeout_ms,
    max_body: settings.max_response_bytes,
  )
}

fn compatibility(
  settings: Settings,
  metadata: protocol.Metadata,
) -> List(Incompatibility) {
  let method = settings.authentication_method(settings)
  let assertion_algorithms = settings.assertion_algorithms(settings)
  let client_checks = [
    #(
      list.contains(metadata.auth_methods, method),
      AuthenticationMethodUnsupported,
    ),
    #(
      assertion_algorithms == []
        || list.any(assertion_algorithms, list.contains(
        metadata.auth_signing_algorithms,
        _,
      )),
      NoCommonAssertionAlgorithm,
    ),
    #(option.is_some(metadata.token_endpoint), MissingTokenEndpoint),
  ]
  let login_checks = [
    #(
      case metadata.code_challenge_methods {
        Some(methods) -> list.contains(methods, "S256")
        // Omitted entirely: acceptable only under the explicit opt-in.
        None -> settings.assume_s256
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
        response_mode_name(settings.response_mode),
      ),
      ResponseModeUnsupported,
    ),
    #(
      list.any(settings.signing_algorithms, list.contains(
        metadata.id_token_algorithms,
        _,
      )),
      NoCommonSigningAlgorithm,
    ),
    #(!metadata.requires_par, RequiresPushedAuthorization),
    #(!metadata.requires_signed_request_object, RequiresRequestObjects),
    #(https_uri(metadata.authorization_endpoint), InsecureAuthorizationEndpoint),
    #(
      option.map(metadata.end_session_endpoint, https_uri)
        |> option.unwrap(True),
      InsecureEndSessionEndpoint,
    ),
  ]
  let checks = case settings.mode {
    settings.RelyingParty ->
      list.append(login_checks, client_checks)
      |> list.sort(fn(a, b) { int.compare(check_order(a.1), check_order(b.1)) })
    settings.ServiceClient -> client_checks
    settings.ResourceServer -> []
  }
  list.filter_map(checks, fn(check) {
    case check.0 {
      True -> Error(Nil)
      False -> Ok(check.1)
    }
  })
}

fn check_order(problem: Incompatibility) -> Int {
  case problem {
    NoS256 -> 0
    AuthorizationCodeGrantUnsupported -> 1
    ResponseModeUnsupported -> 2
    AuthenticationMethodUnsupported -> 3
    NoCommonSigningAlgorithm -> 4
    NoCommonAssertionAlgorithm -> 5
    RequiresPushedAuthorization -> 6
    RequiresRequestObjects -> 7
    InsecureAuthorizationEndpoint -> 8
    InsecureEndSessionEndpoint -> 9
    MissingTokenEndpoint -> 10
  }
}

fn https_uri(value: String) -> Bool {
  case uri.parse(value) {
    Ok(uri.Uri(scheme: Some("https"), host: Some(host), fragment: None, ..)) ->
      host != ""
    _ -> False
  }
}

fn response_mode_name(mode: settings.ResponseMode) -> String {
  case mode {
    settings.Query -> "query"
    settings.FormPost -> "form_post"
  }
}

pub fn describe_start_error(error: StartError) -> String {
  case error {
    InvalidConfig(errors) ->
      "invalid configuration: "
      <> string.join(list.map(errors, config.describe_config_error), "; ")
    DiscoveryFailed(failure) ->
      "provider discovery failed: " <> describe_provider_failure(failure)
    ProviderIncompatible(problems) ->
      "the provider is incompatible with Warden's policy: "
      <> string.join(list.map(problems, describe_incompatibility), "; ")
    StartupTimedOut ->
      "discovery and keys did not load within the startup timeout (with_startup_timeout)"
    AlreadyStarted -> "the client is already started"
    ProcessStartFailed -> "a Warden process failed to start"
  }
}

fn describe_incompatibility(problem: Incompatibility) -> String {
  case problem {
    NoS256 -> "PKCE S256 is not advertised"
    AuthorizationCodeGrantUnsupported ->
      "the authorization code grant is not advertised"
    ResponseModeUnsupported -> "the configured response mode is not advertised"
    AuthenticationMethodUnsupported ->
      "the configured client authentication method is not advertised"
    NoCommonSigningAlgorithm -> "no configured ID-token algorithm is advertised"
    NoCommonAssertionAlgorithm ->
      "no configured client-assertion algorithm is advertised"
    RequiresPushedAuthorization ->
      "the provider requires pushed authorization requests"
    RequiresRequestObjects -> "the provider requires signed request objects"
    InsecureAuthorizationEndpoint -> "the authorization endpoint is not https"
    InsecureEndSessionEndpoint -> "the end-session endpoint is not https"
    MissingTokenEndpoint -> "the provider has no token endpoint"
  }
}

// ===========================================================================
// Failure vocabulary

/// A provider interaction failure, without provider content. May gain
/// variants.
pub type ProviderFailure {
  /// Metadata or keys are not loaded (startup in progress, or the provider
  /// is unreachable); nothing was sent.
  ProviderNotReady
  /// Transport failure, with evidence of whether the request may have
  /// reached the provider.
  TransportFailure(evidence: Evidence, reason: TransportReason)
  /// The provider answered with an error status.
  ProviderStatus(status: Int, error: OAuthError)
  /// The provider's response could not be used.
  MalformedProviderResponse
  /// The provider's metadata issuer differs from the configured issuer.
  IssuerMismatch
  /// A backend failure Warden does not classify further.
  UnclassifiedBackendFailure
}

/// Whether a failed request may have reached the provider.
pub type Evidence {
  /// Proven not sent.
  NotSent
  /// May have been sent.
  MaybeSent
}

/// Closed transport failure reasons. May gain variants as HTTP Gun does.
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
  /// The response failed or ended early after the request may have been
  /// sent (decision D17).
  ReceiveFailed
  UnsupportedContentEncoding
  OtherTransportFailure
}

/// OAuth error codes from provider error responses (IANA registry; may gain
/// variants). Descriptions and URIs are discarded.
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

/// What a caller should do about an error. Closed.
pub type Action {
  /// Send the user through login again.
  Reauthenticate
  /// Nothing was decided; the same operation may be tried again later.
  RetryLater
  /// Pass the carried recovery value to `recover_custody` or
  /// `recover_refresh`; neither contacts the provider again.
  Recover
  /// A configuration or provider-compatibility problem an operator must fix.
  FixConfiguration
  /// The incoming request is invalid (answer 400); do not retry it.
  RejectRequest
}

pub fn describe_provider_failure(failure: ProviderFailure) -> String {
  case failure {
    ProviderNotReady -> "the provider's metadata or keys are not loaded"
    TransportFailure(evidence:, reason:) ->
      telemetry.transport_reason_name(to_telemetry_reason(reason))
      <> case evidence {
        NotSent -> " (not sent)"
        MaybeSent -> " (may have been sent)"
      }
    ProviderStatus(status:, error:) ->
      "the provider answered "
      <> int.to_string(status)
      <> " "
      <> oauth_error_name(error)
    MalformedProviderResponse -> "the provider's response could not be used"
    IssuerMismatch -> "the provider's metadata names another issuer"
    UnclassifiedBackendFailure -> "an unclassified provider failure"
  }
}

fn failure_action(failure: ProviderFailure) -> Action {
  case failure {
    ProviderNotReady | TransportFailure(..) | MalformedProviderResponse ->
      RetryLater
    ProviderStatus(status:, ..) if status >= 500 -> RetryLater
    ProviderStatus(..) | IssuerMismatch -> FixConfiguration
    UnclassifiedBackendFailure -> RetryLater
  }
}

fn oauth_error_name(error: OAuthError) -> String {
  case error {
    InvalidRequest -> "invalid_request"
    InvalidClient -> "invalid_client"
    InvalidGrant -> "invalid_grant"
    UnauthorizedClient -> "unauthorized_client"
    UnsupportedGrantType -> "unsupported_grant_type"
    InvalidScope -> "invalid_scope"
    InvalidToken -> "invalid_token"
    InsufficientScope -> "insufficient_scope"
    OtherOAuthError -> "another OAuth error"
    NoOAuthError -> "without an OAuth error"
  }
}

fn to_telemetry_reason(reason: TransportReason) -> telemetry.TransportReason {
  case reason {
    DestinationRejected -> telemetry.DestinationRejected
    InsecureScheme -> telemetry.InsecureScheme
    InvalidDestination -> telemetry.InvalidDestination
    ResolutionFailed -> telemetry.ResolutionFailed
    ConnectionRefused -> telemetry.ConnectionRefused
    ConnectionFailed -> telemetry.ConnectionFailed
    TlsRejected -> telemetry.TlsRejected
    Timeout -> telemetry.Timeout
    ResponseTooLarge -> telemetry.ResponseTooLarge
    ResponseHeadersTooLarge -> telemetry.ResponseHeadersTooLarge
    MalformedHttp -> telemetry.MalformedHttp
    ReceiveFailed -> telemetry.ReceiveFailed
    UnsupportedContentEncoding -> telemetry.UnsupportedContentEncoding
    OtherTransportFailure -> telemetry.OtherTransportFailure
  }
}

// ===========================================================================
// Login start

/// The browser-binding cookie: a random value Warden sets when a login
/// starts and checks at the callback. Transactions store only its digest.
const binding_cookie = "__Host-warden_binding"

pub type Prompt {
  PromptNone
  PromptLogin
  PromptConsent
  PromptSelectAccount
}

/// Per-login options. Build from `default_login()` with record update, so
/// a new option never breaks the call.
pub type LoginOptions {
  LoginOptions(
    /// Scopes added to the configured scopes for this login.
    scopes: List(String),
    prompt: List(Prompt),
    /// Maximum authentication age. When set, the ID token must carry
    /// `auth_time` within this age.
    max_age: Option(Duration),
    login_hint: Option(String),
    acr_values: List(String),
    ui_locales: List(String),
    /// Extension parameters, such as RFC 8707 `resource`. Reserved
    /// OAuth/OIDC parameter names are rejected.
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

/// A started login: the provider URL and the browser binding to set.
/// `string.inspect` shows neither.
pub opaque type LoginRedirect {
  LoginRedirect(
    url: Redacted(String),
    binding: Redacted(String),
    same_site: cookie.SameSitePolicy,
    max_age: Int,
  )
}

/// The provider authorization URL to send the browser to.
pub fn login_url(redirect: LoginRedirect) -> String {
  redacted.reveal(redirect.url)
}

/// Turn `response` into the login redirect: `303 See Other` to the provider,
/// the browser-binding cookie (`__Host-`, `Secure`, `HttpOnly`, `Path=/`,
/// `SameSite=Lax`, or `None` for form-post callbacks, outliving the pending
/// login by five minutes) and `Cache-Control: no-store`.
pub fn login_response(
  response: Response(b),
  redirect: LoginRedirect,
) -> Response(b) {
  response
  |> response.set_header("location", redacted.reveal(redirect.url))
  |> response.set_header("cache-control", "no-store")
  |> response.set_cookie(
    binding_cookie,
    redacted.reveal(redirect.binding),
    cookie.Attributes(
      max_age: Some(redirect.max_age),
      domain: None,
      path: Some("/"),
      secure: True,
      http_only: True,
      same_site: Some(redirect.same_site),
    ),
  )
  |> fn(r) { response.Response(..r, status: 303) }
}

pub type LoginOptionProblem {
  InvalidOptionScope(String)
  ReservedParameter(String)
  InvalidParameterValue(String)
  /// A login option value longer than 2 KiB.
  OptionTooLong(String)
  InvalidMaxAge
}

const max_option_bytes = 2048

const reserved_parameters = [
  "response_type", "client_id", "redirect_uri", "state", "nonce", "scope",
  "code_challenge", "code_challenge_method", "response_mode", "request",
  "request_uri", "prompt", "max_age", "login_hint", "acr_values", "ui_locales",
  "claims", "dpop_jkt", "iss", "code_verifier", "client_secret",
  "client_assertion", "client_assertion_type", "registration", "id_token_hint",
]

/// Begin a login for the browser that sent `request`: generate state, nonce
/// and PKCE verifier from the OS CSPRNG, store the pending login and return
/// the redirect. A browser that already holds a binding cookie keeps it, so
/// concurrent logins in several tabs stay bound to one cookie.
pub fn begin_login(
  client: Client,
  request: Request(a),
  options: LoginOptions,
) -> Result(LoginRedirect, LoginError) {
  use _ <- result.try(case client.settings.mode {
    settings.RelyingParty -> Ok(Nil)
    _ -> Error(LoginNotConfigured)
  })
  use extension <- result.try(
    login_extension(options) |> result.map_error(InvalidLoginOption),
  )
  use metadata <- result.try(
    native.metadata(client.backend)
    |> result.map_error(fn(f) { LoginProviderUnavailable(provider_failure(f)) }),
  )
  use _ <- result.try(case compatibility(client.settings, metadata) {
    [] -> Ok(Nil)
    problems -> Error(LoginProviderIncompatible(problems))
  })
  let binding = case binding_from(request) {
    Some(binding) -> binding
    None -> secure.random_token(32)
  }
  let state = secure.random_token(32)
  let nonce = secure.random_token(32)
  let verifier = secure.random_token(32)
  let redirect_uri = client.settings.redirect_uri
  let scopes =
    ["openid", ..client.settings.scopes]
    |> list.append(options.scopes)
    |> list.unique
  let mode = response_mode_name(client.settings.response_mode)
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
    client_id: client.settings.client_id,
  ))
  let now = client.settings.clock()
  let lifetime = client.settings.login_lifetime_seconds
  let material =
    logins.Material(
      state:,
      nonce:,
      verifier:,
      redirect_uri:,
      browser_hash: secure.sha256_hex(binding),
      max_age: option.map(options.max_age, whole_seconds),
      created_at: now,
      expires_at: now + lifetime,
    )
  case logins.put(client.logins, login_key(state), material) {
    Ok(Nil) ->
      Ok(LoginRedirect(
        url: redacted.new(url),
        binding: redacted.new(binding),
        same_site: case client.settings.response_mode {
          settings.Query -> cookie.Lax
          settings.FormPost -> cookie.None
        },
        max_age: lifetime + 300,
      ))
    Error(logins.PutFull) -> Error(TooManyPendingLogins)
    Error(logins.PutFailed) -> Error(LoginStoreUnavailable)
  }
}

/// The browser's binding, when its cookie has the shape Warden generates
/// (43 base64url characters).
fn binding_from(request: Request(a)) -> Option(String) {
  request.get_cookies(request)
  |> list.find_map(fn(pair) {
    case pair.0 == binding_cookie && valid_binding(pair.1) {
      True -> Ok(pair.1)
      False -> Error(Nil)
    }
  })
  |> option.from_result
}

fn valid_binding(value: String) -> Bool {
  string.length(value) == 43 && secure.base64url_only(value)
}

fn whole_seconds(value: Duration) -> Int {
  let #(seconds, _) = duration.to_seconds_and_nanoseconds(value)
  seconds
}

fn login_extension(
  options: LoginOptions,
) -> Result(List(#(String, String)), LoginOptionProblem) {
  let long = fn(value) { string.byte_size(value) > max_option_bytes }
  use _ <- result.try(
    list.try_each(options.scopes, fn(scope) {
      case secure.valid_scope(scope) && !long(scope) {
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
          case
            param.0 != ""
            && secure.printable(param.0)
            && secure.printable(param.1)
          {
            False -> Error(InvalidParameterValue(param.0))
            True ->
              case long(param.0) || long(param.1) {
                True -> Error(OptionTooLong(param.0))
                False -> Ok(Nil)
              }
          }
      }
    }),
  )
  use _ <- result.try(case options.max_age {
    Some(age) ->
      case duration.to_milliseconds(age) < 0 {
        True -> Error(InvalidMaxAge)
        False -> Ok(Nil)
      }
    None -> Ok(Nil)
  })
  use values <- result.try(
    list.try_map(
      [
        #("login_hint", option.unwrap(options.login_hint, "")),
        #("acr_values", string.join(options.acr_values, " ")),
        #("ui_locales", string.join(options.ui_locales, " ")),
      ],
      fn(pair) {
        case secure.printable(pair.1), long(pair.1) {
          False, _ -> Error(InvalidParameterValue(pair.0))
          True, True -> Error(OptionTooLong(pair.0))
          True, False -> Ok(pair)
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
    Some(age) -> int.to_string(whole_seconds(age))
    None -> ""
  }
  [#("prompt", prompt), #("max_age", max_age), ..values]
  |> list.filter(fn(pair) { pair.1 != "" })
  |> list.append(options.extra_parameters)
  |> Ok
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
) -> Result(Nil, LoginError) {
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

fn login_key(state: String) -> String {
  "login:" <> secure.sha256_hex(state)
}

// ===========================================================================
// Login completion

/// Why a login did not start, complete or recover. May gain variants;
/// branch on `login_error_action`.
pub type LoginError {
  /// A login option is invalid.
  InvalidLoginOption(LoginOptionProblem)
  /// The client was built with `service_client` or `resource_server`.
  LoginNotConfigured
  /// Provider metadata is unavailable.
  LoginProviderUnavailable(ProviderFailure)
  /// Provider metadata is no longer compatible with Warden's policy.
  LoginProviderIncompatible(List(Incompatibility))
  /// The login store did not confirm the new login.
  LoginStoreUnavailable
  /// The login store is at capacity.
  TooManyPendingLogins
  /// The callback is not a well-formed authorization response. No login was
  /// touched.
  CallbackMalformed(CallbackProblem)
  /// The callback does not match a pending login of this browser. No login
  /// was consumed.
  CallbackRejected(BindingProblem)
  /// The login expired before its callback was consumed.
  LoginExpired
  /// The login was already consumed by another callback.
  LoginReplayed
  /// The stored login changed between check and consumption.
  LoginChanged
  /// The login store did not answer; the login may or may not have been
  /// consumed. Nothing was sent to the provider.
  TransactionStoreUnavailable
  /// The stored login did not open (tampering, or an unknown sealing key).
  LoginRecordUnreadable
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
  /// The login timeout ran out before the code was exchanged; nothing was
  /// sent. The login is consumed.
  LoginTimedOut
  /// Identity was verified and custody installation was submitted, but its
  /// outcome is unknown. Call `recover_custody`; the authorization code is
  /// never exchanged again.
  CustodyUnconfirmed(CustodyRecovery)
  /// The recovery belongs to a different client configuration.
  RecoveryForeign
  /// The session this recovery installed has since ended; the recovery
  /// cannot bring it back.
  RecoveryEnded
  /// The recovery is older than the login lifetime; it is neither confirmed
  /// nor installed again. Start a new login.
  RecoveryExpired
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
  /// A query callback arrived while form-post is configured, the reverse,
  /// or another HTTP method.
  UnexpectedResponseMode
}

pub type BindingProblem {
  /// No pending login has this state.
  UnknownState
  /// The browser-binding cookie is absent.
  BrowserBindingMissing
  /// The browser binding does not belong to this login.
  BrowserBindingMismatch
  /// `iss` differs from the configured issuer (RFC 9207).
  CallbackIssuerMismatch
  /// `iss` is required by policy but absent.
  CallbackIssuerMissing
}

/// Provider error codes (RFC 6749 §4.1.2.1, OIDC Core §3.1.2.6). May gain
/// variants. Descriptions are discarded.
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

/// Why a verified-looking ID token was not accepted. May gain variants.
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
  /// `max_age` was requested and `auth_time` is absent, in the future, or
  /// too old.
  AuthenticationTooOld
  MalformedIdToken
  UnclassifiedIdentityFailure
}

/// Complete a login from the callback request (a `GET` with the query, or
/// a form `POST`, per the configured response mode) and the browser's
/// binding cookie.
///
/// Order: parse strictly; find the pending login by state; compare state,
/// browser binding and issuer without consuming; consume atomically; only a
/// consumption confirmed by the store proceeds to exchange the code; verify
/// the identity; install custody. The whole operation is bounded by the
/// login timeout (default 30 s).
pub fn complete_login(
  client: Client,
  request: Request(String),
) -> Result(Session, LoginError) {
  let started = secure.monotonic_ms()
  let result = case client.settings.mode {
    settings.RelyingParty -> complete(client, request, started)
    _ -> Error(LoginNotConfigured)
  }
  emit_login(client, result, started)
  result
}

fn complete(
  client: Client,
  request: Request(String),
  started: Int,
) -> Result(Session, LoginError) {
  let deadline = started + client.settings.login_timeout_ms
  let remaining = fn() { deadline - secure.monotonic_ms() }
  let logins_within = fn() {
    logins.Logins(
      ..client.logins,
      port: port.within(client.logins.port, remaining()),
    )
  }
  use parsed <- result.try(parse_callback(client, request))
  let state = case parsed {
    callback.CodeResponse(state:, ..) | callback.ErrorResponse(state:, ..) ->
      state
  }
  let key = login_key(state)
  use lookup <- result.try(
    logins.get(logins_within(), key)
    |> result.replace_error(TransactionStoreUnavailable),
  )
  use #(material, version) <- result.try(case lookup {
    logins.Found(material:, version:) -> Ok(#(material, version))
    logins.FoundConsumed -> Error(LoginReplayed)
    logins.FoundExpired -> Error(LoginExpired)
    logins.NotFound -> Error(CallbackRejected(UnknownState))
    logins.Unreadable -> Error(LoginRecordUnreadable)
  })
  use _ <- result.try(check_binding(client, parsed, material, request))
  use decision <- result.try(
    logins.consume(logins_within(), key, material, version)
    |> result.replace_error(TransactionStoreUnavailable),
  )
  use material <- result.try(case decision {
    logins.Consumed(material) -> Ok(material)
    logins.AlreadyConsumed -> Error(LoginReplayed)
    logins.Expired -> Error(LoginExpired)
    logins.Changed -> Error(LoginChanged)
    logins.Missing -> Error(CallbackRejected(UnknownState))
  })
  case parsed {
    callback.ErrorResponse(error:, ..) -> Error(ProviderDenied(denial(error)))
    callback.CodeResponse(code:, ..) ->
      case remaining() > 0 {
        False -> Error(LoginTimedOut)
        True -> exchange(client, material, code, remaining)
      }
  }
}

fn parse_callback(
  client: Client,
  request: Request(String),
) -> Result(callback.Parsed, LoginError) {
  let mode = client.settings.response_mode
  use raw <- result.try(case request.method, mode {
    http.Get, settings.Query -> Ok(option.unwrap(request.query, ""))
    http.Post, settings.FormPost ->
      case request.get_header(request, "content-type") {
        Ok(content_type) ->
          case
            string.starts_with(
              string.lowercase(string.trim(content_type)),
              "application/x-www-form-urlencoded",
            )
          {
            True -> Ok(request.body)
            False -> Error(CallbackMalformed(CallbackEncodingInvalid))
          }
        Error(Nil) -> Error(CallbackMalformed(CallbackEncodingInvalid))
      }
    _, _ -> Error(CallbackMalformed(UnexpectedResponseMode))
  })
  callback.parse(raw, mode == settings.FormPost)
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

fn check_binding(
  client: Client,
  parsed: callback.Parsed,
  material: logins.Material,
  request: Request(String),
) -> Result(Nil, LoginError) {
  let #(state, issuer) = case parsed {
    callback.CodeResponse(state:, issuer:, ..)
    | callback.ErrorResponse(state:, issuer:, ..) -> #(state, issuer)
  }
  use _ <- result.try(case secure.constant_time_equal(state, material.state) {
    True -> Ok(Nil)
    False -> Error(CallbackRejected(UnknownState))
  })
  use binding <- result.try(case binding_from(request) {
    Some(binding) -> Ok(binding)
    None -> Error(CallbackRejected(BrowserBindingMissing))
  })
  use _ <- result.try(
    case
      secure.constant_time_equal(
        secure.sha256_hex(binding),
        material.browser_hash,
      )
    {
      True -> Ok(Nil)
      False -> Error(CallbackRejected(BrowserBindingMismatch))
    },
  )
  let configured_issuer = client.settings.issuer
  case issuer {
    Some(value) ->
      case value == configured_issuer {
        True -> Ok(Nil)
        False -> Error(CallbackRejected(CallbackIssuerMismatch))
      }
    None -> {
      let required = case client.settings.always_require_issuer {
        True -> True
        False ->
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
  material: logins.Material,
  code: String,
  remaining: fn() -> Int,
) -> Result(Session, LoginError) {
  let exchanged =
    native.exchange_code(
      native.within(client.backend, remaining()),
      code:,
      redirect_uri: material.redirect_uri,
      nonce: material.nonce,
      verifier: material.verifier,
    )
  use response <- result.try(exchanged |> result.map_error(exchange_failure))
  use #(identity, sealed_identity) <- result.try(
    accept_identity(client, material, response)
    |> result.map_error(IdentityRejected),
  )
  install(client, identity, sealed_identity, material, response, remaining)
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
/// these checks bind the result to the consumed login and fail closed if a
/// backend did not.
fn accept_identity(
  client: Client,
  material: logins.Material,
  response: protocol.TokenResponse,
) -> Result(#(VerifiedIdentity, custody.Identity), IdentityProblem) {
  use id_token <- result.try(
    case response.id_token, response.id_token_malformed {
      Some(id_token), False -> Ok(id_token)
      _, True -> Error(MalformedIdToken)
      None, False -> Error(MissingIdToken)
    },
  )
  let claims = id_token.claims
  let issuer = client.settings.issuer
  let client_id = client.settings.client_id
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
        Some(auth_time) -> {
          let age = client.settings.clock() - auth_time
          // A future authentication time is not a recent authentication,
          // beyond the provider clock tolerance.
          let tolerance = client.settings.clock_tolerance_seconds
          case age >= 0 - tolerance && age <= max_age {
            True -> Ok(Nil)
            False -> Error(AuthenticationTooOld)
          }
        }
        None -> Error(AuthenticationTooOld)
      }
  })
  use _ <- result.try(case response.access_token {
    Some(_) -> Ok(Nil)
    None -> Error(MalformedIdToken)
  })
  // The verified payload, exactly as signed, is what custody seals.
  use claims_json <- result.try(
    payload_text(id_token.token) |> result.replace_error(MalformedIdToken),
  )
  Ok(#(
    VerifiedIdentity(issuer:, subject:, claims: redacted.new(claims)),
    custody.Identity(issuer:, subject:, claims: claims_json),
  ))
}

fn payload_text(token: String) -> Result(String, Nil) {
  case string.split(token, ".") {
    [_, payload, _] ->
      bit_array.base64_url_decode(payload) |> result.try(bit_array.to_string)
    _ -> Error(Nil)
  }
}

// ===========================================================================
// Identity

/// A verified identity. Constructed only by this module after verification
/// and Warden's binding checks. The stable key is `(issuer, subject)`;
/// email is an optional claim, never a key.
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

/// `auth_time`, when the provider included it.
pub fn authentication_time(identity: VerifiedIdentity) -> Option(Timestamp) {
  protocol.int_claim(redacted.reveal(identity.claims), "auth_time")
  |> option.map(timestamp.from_unix_seconds)
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

fn identity_from(
  sealed: custody.Identity,
) -> Result(VerifiedIdentity, SessionError) {
  json.parse(sealed.claims, decode.dynamic)
  |> result.map(fn(claims) {
    VerifiedIdentity(
      issuer: sealed.issuer,
      subject: sealed.subject,
      claims: redacted.new(claims),
    )
  })
  |> result.replace_error(SessionRecordUnreadable)
}

// ===========================================================================
// Sessions and custody

/// A session whose installation custody confirmed. It carries the verified
/// identity and a custody reference and revision; tokens stay in custody.
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

/// The custody reference, for the application's own session cookie or
/// store. It is a random bearer value: keep it server-side or in an
/// encrypted, `HttpOnly` cookie. Custody stores only its digest.
pub fn session_reference(session: Session) -> String {
  redacted.reveal(session.reference)
}

/// Recovery for an installation whose outcome is unknown. It retains the
/// exact installation command, including token material; recovering never
/// exchanges the authorization code again.
pub opaque type CustodyRecovery {
  CustodyRecovery(provider: String, command: Redacted(custody.Install))
}

fn install(
  client: Client,
  identity: VerifiedIdentity,
  sealed_identity: custody.Identity,
  material: logins.Material,
  response: protocol.TokenResponse,
  remaining: fn() -> Int,
) -> Result(Session, LoginError) {
  let now = client.settings.clock()
  let tokens =
    custody.Tokens(
      access_token: option.unwrap(response.access_token, ""),
      token_type: response.token_type,
      expires_at: option.map(response.expires_in, fn(s) { now + s }),
      refresh_token: response.refresh_token,
      id_token: option.map(response.id_token, fn(t) { t.token }),
      scopes: response.scopes,
    )
  let command =
    custody.Install(
      reference: custody.new_reference(client.custody),
      command_id: secure.random_token(24),
      issued_at: now,
      provider: client.provider,
      identity: sealed_identity,
      evidence: custody.Evidence(
        nonce: material.nonce,
        auth_time: protocol.int_claim(
          redacted.reveal(identity.claims),
          "auth_time",
        ),
      ),
      tokens:,
    )
  let recovery =
    CustodyRecovery(provider: client.provider, command: redacted.new(command))
  case remaining() > 0 {
    False -> Error(CustodyUnconfirmed(recovery))
    True ->
      submit_install(
        client,
        custody.Custody(
          ..client.custody,
          port: port.within(client.custody.port, remaining()),
        ),
        recovery,
        identity,
      )
  }
}

fn submit_install(
  client: Client,
  owner: custody.Custody,
  recovery: CustodyRecovery,
  identity: VerifiedIdentity,
) -> Result(Session, LoginError) {
  let command = redacted.reveal(recovery.command)
  case custody.install(owner, command) {
    custody.Installed(revision:) ->
      Ok(Session(
        identity:,
        reference: redacted.new(command.reference),
        revision:,
        provider: client.provider,
      ))
    custody.InstallEnded -> Error(RecoveryEnded)
    custody.InstallExpired -> Error(RecoveryExpired)
    custody.InstallUnknown -> Error(CustodyUnconfirmed(recovery))
  }
}

/// Resubmit an installation whose outcome was unknown. Custody returns the
/// original session if it already accepted the command.
pub fn recover_custody(
  client: Client,
  recovery: CustodyRecovery,
) -> Result(Session, LoginError) {
  let started = secure.monotonic_ms()
  let result = case recovery.provider == client.provider {
    False -> Error(RecoveryForeign)
    True -> {
      let command = redacted.reveal(recovery.command)
      case identity_from(command.identity) {
        Ok(identity) ->
          submit_install(client, client.custody, recovery, identity)
        Error(_) -> Error(RecoveryEnded)
      }
    }
  }
  emit_login(client, result, started)
  result
}

/// What to do about a login error.
pub fn login_error_action(error: LoginError) -> Action {
  case error {
    InvalidLoginOption(_) | LoginNotConfigured -> FixConfiguration
    LoginProviderIncompatible(_) -> FixConfiguration
    LoginProviderUnavailable(failure) -> failure_action(failure)
    LoginStoreUnavailable | TooManyPendingLogins -> RetryLater
    CallbackMalformed(_) | CallbackRejected(_) -> RejectRequest
    LoginRecordUnreadable -> RejectRequest
    LoginExpired | LoginReplayed | LoginChanged -> Reauthenticate
    TransactionStoreUnavailable -> Reauthenticate
    ProviderDenied(TemporarilyUnavailable) | ProviderDenied(ServerError) ->
      Reauthenticate
    ProviderDenied(_) -> Reauthenticate
    ProviderUnavailableBeforeExchange(_) -> Reauthenticate
    ExchangeRejected(InvalidClient) | ExchangeRejected(UnauthorizedClient) ->
      FixConfiguration
    ExchangeRejected(_) | ExchangeOutcomeUnknown | LoginTimedOut ->
      Reauthenticate
    IdentityRejected(_) -> Reauthenticate
    CustodyUnconfirmed(_) -> Recover
    RecoveryForeign -> FixConfiguration
    RecoveryEnded | RecoveryExpired -> Reauthenticate
  }
}

pub fn describe_login_error(error: LoginError) -> String {
  case error {
    InvalidLoginOption(problem) ->
      "invalid login option: "
      <> case problem {
        InvalidOptionScope(scope) -> "scope " <> string.inspect(scope)
        ReservedParameter(name) -> "reserved parameter " <> string.inspect(name)
        InvalidParameterValue(name) ->
          "invalid value for " <> string.inspect(name)
        OptionTooLong(name) -> string.inspect(name) <> " is longer than 2 KiB"
        InvalidMaxAge -> "max_age is negative"
      }
    LoginNotConfigured -> "this client is not configured for login"
    LoginProviderUnavailable(failure) ->
      "provider unavailable: " <> describe_provider_failure(failure)
    LoginProviderIncompatible(problems) ->
      "the provider is incompatible: "
      <> string.join(list.map(problems, describe_incompatibility), "; ")
    LoginStoreUnavailable -> "the login store did not confirm the login"
    TooManyPendingLogins ->
      "the login store is at capacity (with_max_pending_logins)"
    CallbackMalformed(problem) ->
      "malformed callback: " <> callback_problem_name(problem)
    CallbackRejected(problem) ->
      "callback rejected: " <> binding_problem_name(problem)
    LoginExpired -> "the login expired"
    LoginReplayed -> "the login was already completed"
    LoginChanged -> "the login changed while it was being completed"
    TransactionStoreUnavailable ->
      "the login store did not answer; nothing was sent"
    LoginRecordUnreadable -> "the stored login did not open"
    ProviderDenied(_) -> "the provider denied the login"
    ProviderUnavailableBeforeExchange(failure) ->
      "the code was not exchanged: " <> describe_provider_failure(failure)
    ExchangeRejected(error) ->
      "the token endpoint rejected the code: " <> oauth_error_name(error)
    ExchangeOutcomeUnknown -> "the code exchange outcome is unknown"
    IdentityRejected(problem) ->
      "the identity was not accepted: " <> identity_problem_name(problem)
    LoginTimedOut ->
      "the login timeout ran out before the code exchange (with_login_timeout)"
    CustodyUnconfirmed(_) ->
      "session installation was not confirmed; call recover_custody"
    RecoveryForeign -> "the recovery belongs to another client"
    RecoveryEnded -> "the recovered session has ended"
    RecoveryExpired -> "the recovery is too old"
  }
}

fn callback_problem_name(problem: CallbackProblem) -> String {
  case problem {
    CallbackTooLarge -> "too large"
    CallbackEncodingInvalid -> "invalid encoding"
    DuplicateCallbackParameter -> "duplicate parameter"
    MissingState -> "missing state"
    MissingCode -> "missing code"
    EmptyCode -> "empty code"
    AmbiguousCallback -> "both code and error"
    InvalidCallbackValue -> "invalid value"
    UnexpectedResponseMode -> "unexpected response mode or method"
  }
}

fn binding_problem_name(problem: BindingProblem) -> String {
  case problem {
    UnknownState -> "unknown state"
    BrowserBindingMissing -> "browser binding cookie missing"
    BrowserBindingMismatch -> "browser binding mismatch"
    CallbackIssuerMismatch -> "iss mismatch"
    CallbackIssuerMissing -> "iss missing"
  }
}

fn identity_problem_name(problem: IdentityProblem) -> String {
  case problem {
    MissingIdToken -> "missing_id_token"
    BadSignature -> "bad_signature"
    AlgorithmNotAllowed -> "algorithm_not_allowed"
    UnsignedIdToken -> "unsigned"
    EncryptedUnsignedIdToken -> "encrypted_unsigned"
    EncryptedIdTokenUnsupported -> "encrypted_unsupported"
    UnknownSigningKey -> "unknown_signing_key"
    IdTokenIssuerMismatch -> "issuer_mismatch"
    IdTokenAudienceMismatch -> "audience_mismatch"
    AuthorizedPartyMismatch -> "authorized_party_mismatch"
    IdTokenExpired -> "expired"
    IdTokenNotYetValid -> "not_yet_valid"
    NonceMismatch -> "nonce_mismatch"
    AccessTokenHashMismatch -> "access_token_hash_mismatch"
    MissingClaim(claim) -> "missing_claim:" <> claim
    SubjectMismatch -> "subject_mismatch"
    AuthenticationTooOld -> "authentication_too_old"
    MalformedIdToken -> "malformed"
    UnclassifiedIdentityFailure -> "unclassified"
  }
}

fn identity_problem_from_name(name: String) -> IdentityProblem {
  case name {
    "missing_id_token" -> MissingIdToken
    "bad_signature" -> BadSignature
    "algorithm_not_allowed" -> AlgorithmNotAllowed
    "unsigned" -> UnsignedIdToken
    "encrypted_unsigned" -> EncryptedUnsignedIdToken
    "encrypted_unsupported" -> EncryptedIdTokenUnsupported
    "unknown_signing_key" -> UnknownSigningKey
    "issuer_mismatch" -> IdTokenIssuerMismatch
    "audience_mismatch" -> IdTokenAudienceMismatch
    "authorized_party_mismatch" -> AuthorizedPartyMismatch
    "expired" -> IdTokenExpired
    "not_yet_valid" -> IdTokenNotYetValid
    "nonce_mismatch" -> NonceMismatch
    "access_token_hash_mismatch" -> AccessTokenHashMismatch
    "missing_claim:" <> claim -> MissingClaim(claim)
    "subject_mismatch" -> SubjectMismatch
    "authentication_too_old" -> AuthenticationTooOld
    "malformed" -> MalformedIdToken
    _ -> UnclassifiedIdentityFailure
  }
}

fn emit_login(
  client: Client,
  result: Result(Session, LoginError),
  started: Int,
) -> Nil {
  let outcome = case result {
    Ok(_) -> telemetry.LoginSucceeded
    Error(error) ->
      case error {
        CallbackMalformed(_)
        | CallbackRejected(_)
        | LoginExpired
        | LoginReplayed
        | LoginChanged
        | LoginRecordUnreadable -> telemetry.LoginCallbackRefused
        ProviderDenied(_) -> telemetry.LoginDenied
        ProviderUnavailableBeforeExchange(_)
        | ExchangeRejected(_)
        | ExchangeOutcomeUnknown -> telemetry.LoginExchangeFailed
        IdentityRejected(_) -> telemetry.LoginIdentityRejected
        CustodyUnconfirmed(_) -> telemetry.LoginCustodyUnconfirmed
        RecoveryEnded | RecoveryExpired | RecoveryForeign ->
          telemetry.LoginCallbackRefused
        _ -> telemetry.LoginUnavailable
      }
  }
  sinal.emit(
    telemetry.login(),
    telemetry.SessionMeasurements(duration_ms: secure.monotonic_ms() - started),
    telemetry.Login(outcome:, correlation: client.correlation),
  )
}

// ===========================================================================
// Session access

/// Why a session operation failed. May gain variants; branch on
/// `session_error_action`.
pub type SessionError {
  /// No live session has this reference: unknown, logged out, or past its
  /// absolute or idle lifetime.
  SessionNotFound
  /// The session was held by the in-memory custody, which restarted since.
  SessionLost
  /// The session belongs to another client configuration.
  SessionForeign
  /// The custody store did not answer.
  SessionStoreUnavailable
  /// The stored session did not open (tampering, or an unknown sealing
  /// key).
  SessionRecordUnreadable
  /// The session has no access token.
  SessionHasNoAccessToken
  /// The access token expired and the session has no refresh token.
  RefreshTokenUnavailable
  /// The refresh token was rejected (`invalid_grant`): revoked or expired.
  RefreshRevoked
  /// The token endpoint refused the refresh before processing the grant
  /// (RFC 6749 §5.2); the refresh token may be sent again later.
  RefreshRejected(OAuthError)
  /// The refresh request was proven not sent; it may be tried again.
  RefreshNotSent(ProviderFailure)
  /// The provider may have rotated the refresh token, so it is never sent
  /// again. Reauthenticate.
  RefreshQuarantined(QuarantineReason)
  /// Another request's refresh of this session did not settle within the
  /// refresh wait (default 5 s).
  RefreshWaitTimedOut
  /// New tokens were received but custody did not confirm publishing them.
  /// Call `recover_refresh`; the provider is not called again.
  RefreshUnconfirmed(RefreshRecovery)
  /// The refresh recovery belongs to another client configuration.
  RefreshRecoveryForeign
}

pub type QuarantineReason {
  /// The refresh request may have reached the provider; its outcome is
  /// unknown.
  ProviderOutcomeUnknown
  /// The provider answered, but the response was not acceptable.
  ResponseRejected(RefreshValidationError)
  /// The refreshing request's lease ran out before it settled.
  RefresherLost
}

/// Why a refresh response was not accepted. May gain variants.
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

/// Publication-phase recovery: the exact publication command, with the new
/// tokens. It cannot authorise another provider call.
pub opaque type RefreshRecovery {
  RefreshRecovery(
    provider: String,
    command: Redacted(custody.Publish),
    identity: VerifiedIdentity,
  )
}

/// An access token. `string.inspect` shows no token value.
pub opaque type AccessToken {
  AccessToken(reveal: fn() -> String, token_type: String)
}

/// A usable access token for the session, with the session at its current
/// revision.
pub type Access {
  Access(
    session: Session,
    token: AccessToken,
    /// When the provider stated a lifetime.
    expires_at: Option(Timestamp),
    scopes: List(String),
  )
}

/// The token value, for a client that does not take a gleam_http request.
/// Treat it as a secret: do not log or persist it.
pub fn access_token_value(token: AccessToken) -> String {
  token.reveal()
}

pub fn access_token_type(token: AccessToken) -> String {
  token.token_type
}

/// Set `Authorization: Bearer <token>` on a resource request.
pub fn authorize(request: Request(a), token: AccessToken) -> Request(a) {
  request.set_header(request, "authorization", "Bearer " <> token.reveal())
}

fn new_access_token(value: String, token_type: String) -> AccessToken {
  AccessToken(reveal: fn() { value }, token_type:)
}

/// Load a session from its custody reference (the application's session
/// cookie).
pub fn restore_session(
  client: Client,
  reference: String,
) -> Result(Session, SessionError) {
  use snapshot <- result.try(load(client, reference))
  session_of(client, snapshot)
}

fn load(
  client: Client,
  reference: String,
) -> Result(custody.Snapshot, SessionError) {
  case custody.get(client.custody, reference) {
    Error(error) -> Error(read_error(error))
    Ok(snapshot) if snapshot.entry.provider != client.provider ->
      Error(SessionForeign)
    Ok(snapshot) -> Ok(snapshot)
  }
}

fn read_error(error: custody.ReadError) -> SessionError {
  case error {
    custody.Missing -> SessionNotFound
    custody.Lost -> SessionLost
    custody.Unreadable -> SessionRecordUnreadable
    custody.Unavailable -> SessionStoreUnavailable
  }
}

fn session_of(
  client: Client,
  snapshot: custody.Snapshot,
) -> Result(Session, SessionError) {
  use identity <- result.map(identity_from(snapshot.entry.identity))
  Session(
    identity:,
    reference: redacted.new(snapshot.reference),
    revision: snapshot.entry.revision,
    provider: client.provider,
  )
}

fn access_of(
  client: Client,
  snapshot: custody.Snapshot,
) -> Result(Access, SessionError) {
  use session <- result.try(session_of(client, snapshot))
  let tokens = snapshot.entry.tokens
  case tokens.access_token {
    "" -> Error(SessionHasNoAccessToken)
    value ->
      Ok(Access(
        session:,
        token: new_access_token(value, tokens.token_type),
        expires_at: option.map(tokens.expires_at, timestamp.from_unix_seconds),
        scopes: tokens.scopes,
      ))
  }
}

/// A usable access token for the session. When the current token expires
/// within the refresh margin (default 30 s) it refreshes first; when
/// another request is already refreshing this session it waits for that
/// refresh (default at most 5 s) instead of sending a second one; when the
/// session value is older than custody's, it uses the current revision. If
/// a refresh decides nothing (`RetryLater`) while the current token has not
/// expired, the current token is returned.
pub fn access_token(
  client: Client,
  session: Session,
) -> Result(Access, SessionError) {
  use _ <- result.try(same_provider(client, session))
  use snapshot <- result.try(load(client, redacted.reveal(session.reference)))
  let now = client.settings.clock()
  case snapshot.entry.tokens.expires_at {
    Some(expires_at)
      if expires_at - now <= client.settings.refresh_margin_seconds
    -> {
      let usable = expires_at > now
      case refresh_from(client, snapshot, usable) {
        // A refresh that decided nothing (not sent, store or wait timeout)
        // leaves the current token in use while it has not expired.
        Error(error) ->
          case usable && session_error_action(error) == RetryLater {
            True -> access_of(client, snapshot)
            False -> Error(error)
          }
        ok -> ok
      }
    }
    _ -> access_of(client, snapshot)
  }
}

/// Refresh the session now, for example after a resource server answered
/// 401. If the session was already refreshed since this value was read, the
/// current token is returned without another refresh. Concurrent callers
/// share one refresh as in `access_token`.
pub fn refresh(
  client: Client,
  session: Session,
) -> Result(Access, SessionError) {
  use _ <- result.try(same_provider(client, session))
  use snapshot <- result.try(load(client, redacted.reveal(session.reference)))
  case snapshot.entry.revision > session.revision {
    True -> access_of(client, snapshot)
    False -> refresh_from(client, snapshot, False)
  }
}

fn same_provider(
  client: Client,
  session: Session,
) -> Result(Nil, SessionError) {
  case session.provider == client.provider {
    True -> Ok(Nil)
    False -> Error(SessionForeign)
  }
}

/// Refresh from `snapshot`. `usable`: the current token has not expired, so
/// it may be returned when no refresh is possible.
fn refresh_from(
  client: Client,
  snapshot: custody.Snapshot,
  usable: Bool,
) -> Result(Access, SessionError) {
  let started = secure.monotonic_ms()
  let deadline = started + client.settings.refresh_wait_ms
  let #(result, outcome) =
    attempt_refresh(client, snapshot, usable, deadline, 20, False)
  case outcome {
    Some(outcome) ->
      sinal.emit(
        telemetry.refresh(),
        telemetry.SessionMeasurements(
          duration_ms: secure.monotonic_ms() - started,
        ),
        telemetry.Refresh(outcome:, correlation: client.correlation),
      )
    None -> Nil
  }
  result
}

fn lease_seconds(settings: Settings) -> Int {
  { settings.request_timeout_ms + 2 * settings.store_timeout_ms } / 1000 + 1
}

/// One reservation attempt; waits and tries again while another request
/// holds the reservation. Returns the result and the telemetry outcome.
fn attempt_refresh(
  client: Client,
  snapshot: custody.Snapshot,
  usable: Bool,
  deadline: Int,
  pause: Int,
  waited: Bool,
) -> #(Result(Access, SessionError), Option(telemetry.RefreshOutcome)) {
  let reference = snapshot.reference
  let command_id = secure.random_token(24)
  case
    custody.reserve(
      client.custody,
      reference,
      client.provider,
      snapshot.entry.revision,
      command_id,
      lease_seconds(client.settings),
    )
  {
    custody.Reserved(dispatch) -> dispatch_refresh(client, dispatch)
    custody.Busy ->
      case secure.monotonic_ms() + pause < deadline {
        False -> #(
          Error(RefreshWaitTimedOut),
          Some(telemetry.RefreshWaitTimedOut),
        )
        True -> {
          process.sleep(pause)
          // Re-read: the winner may have published a new revision.
          case load(client, reference) {
            Error(error) -> #(Error(error), None)
            Ok(current) ->
              case current.entry.revision > snapshot.entry.revision {
                True -> #(
                  access_of(client, current),
                  Some(telemetry.RefreshJoined),
                )
                False ->
                  attempt_refresh(
                    client,
                    current,
                    usable,
                    deadline,
                    int.min(pause * 2, 250),
                    True,
                  )
              }
          }
        }
      }
    custody.Stale(current) -> #(access_of(client, current), case waited {
      True -> Some(telemetry.RefreshJoined)
      False -> None
    })
    custody.ReservationQuarantined(reason) -> #(
      Error(RefreshQuarantined(quarantine_from(reason))),
      Some(telemetry.RefreshQuarantined),
    )
    custody.ReservationRevoked -> #(
      Error(RefreshRevoked),
      Some(telemetry.RefreshRevoked),
    )
    custody.NoRefreshToken(current) ->
      case usable {
        True -> #(access_of(client, current), None)
        False -> #(Error(RefreshTokenUnavailable), None)
      }
    custody.ReservationFailed(error) -> #(
      Error(read_error(error)),
      Some(telemetry.RefreshUnavailable),
    )
    custody.ReservationUnknown -> #(
      Error(SessionStoreUnavailable),
      Some(telemetry.RefreshUnavailable),
    )
  }
}

fn dispatch_refresh(
  client: Client,
  dispatch: custody.Dispatch,
) -> #(Result(Access, SessionError), Option(telemetry.RefreshOutcome)) {
  let outcome =
    native.refresh(client.backend, refresh_token: dispatch.refresh_token)
  let settle = fn(settlement, error, event) {
    case
      custody.settle(
        client.custody,
        dispatch.reference,
        dispatch.dispatch_id,
        settlement,
      )
    {
      True -> #(Error(error), Some(event))
      // Unsettled: the lease will run out and quarantine the generation.
      False -> #(
        Error(SessionStoreUnavailable),
        Some(telemetry.RefreshUnavailable),
      )
    }
  }
  let quarantine = fn(reason) {
    settle(
      custody.SettleQuarantine(quarantine_name(reason)),
      RefreshQuarantined(reason),
      telemetry.RefreshQuarantined,
    )
  }
  case outcome {
    Error(failure) ->
      case failure {
        protocol.NotReady
        | protocol.Policy(_)
        | protocol.Transport(sent: False, ..) ->
          settle(
            custody.SettleNotSent,
            RefreshNotSent(provider_failure(failure)),
            telemetry.RefreshNotSent,
          )
        protocol.Endpoint(status:, error:) if status == 400 || status == 401 ->
          case oauth_error(error) {
            InvalidGrant ->
              settle(
                custody.SettleRejected,
                RefreshRevoked,
                telemetry.RefreshRevoked,
              )
            code ->
              case code {
                // These codes say the request was refused before the grant
                // was processed (RFC 6749 §5.2): release the generation.
                InvalidRequest
                | InvalidClient
                | UnauthorizedClient
                | UnsupportedGrantType
                | InvalidScope ->
                  settle(
                    custody.SettleNotSent,
                    RefreshRejected(code),
                    telemetry.RefreshRejected,
                  )
                // Anything else may follow processing: never send it again.
                _ -> quarantine(ProviderOutcomeUnknown)
              }
          }
        protocol.IdTokenInvalid(reason:, claim:) ->
          quarantine(
            ResponseRejected(
              RefreshedIdTokenInvalid(identity_problem(reason, claim)),
            ),
          )
        protocol.Malformed ->
          quarantine(ResponseRejected(RefreshResponseMalformed))
        protocol.Transport(sent: True, ..)
        | protocol.Endpoint(..)
        | protocol.UserinfoSubjectMismatch
        | protocol.Unmapped -> quarantine(ProviderOutcomeUnknown)
      }
    Ok(response) ->
      case refreshed_update(client, dispatch, response) {
        Error(problem) -> quarantine(ResponseRejected(problem))
        Ok(update) -> {
          let command =
            custody.Publish(
              reference: dispatch.reference,
              provider: client.provider,
              dispatch_id: dispatch.dispatch_id,
              command_id: dispatch.command_id,
              update:,
            )
          case identity_from(dispatch.identity) {
            Error(error) -> #(Error(error), None)
            Ok(identity) -> {
              let result =
                publish(
                  client,
                  RefreshRecovery(
                    provider: client.provider,
                    command: redacted.new(command),
                    identity:,
                  ),
                )
              #(
                result,
                Some(case result {
                  Ok(_) -> telemetry.Refreshed
                  Error(RefreshUnconfirmed(_)) -> telemetry.RefreshUnconfirmed
                  Error(RefreshQuarantined(_)) -> telemetry.RefreshQuarantined
                  Error(_) -> telemetry.RefreshUnavailable
                }),
              )
            }
          }
        }
      }
  }
}

/// Continuity of the refreshed ID token with the original authentication
/// (OIDC Core §12.2) and the unchanged-scope profile.
fn refreshed_update(
  client: Client,
  dispatch: custody.Dispatch,
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
  let client_id = client.settings.client_id
  use id_token <- result.try(case response.id_token {
    Some(id_token) -> {
      let claims = id_token.claims
      let original = dispatch.identity
      use _ <- result.try(case protocol.string_claim(claims, "iss") {
        Some(value) if value == original.issuer -> Ok(Nil)
        _ -> Error(RefreshedIssuerMismatch)
      })
      use _ <- result.try(case protocol.string_claim(claims, "sub") {
        Some(value) if value == original.subject -> Ok(Nil)
        _ -> Error(RefreshedSubjectMismatch)
      })
      use _ <- result.try(case protocol.audiences(claims) == [client_id] {
        True -> Ok(Nil)
        False -> Error(RefreshedAudienceMismatch)
      })
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
  let now = client.settings.clock()
  Ok(custody.Update(
    access_token: access,
    token_type: response.token_type,
    expires_at: option.map(response.expires_in, fn(s) { now + s }),
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
  recovery: RefreshRecovery,
) -> Result(Access, SessionError) {
  let command = redacted.reveal(recovery.command)
  case custody.publish(client.custody, command) {
    custody.Published(snapshot) -> access_of(client, snapshot)
    custody.PublishRejected -> Error(RefreshQuarantined(RefresherLost))
    custody.PublishFailed(error) -> Error(read_error(error))
    custody.PublishUnknown -> Error(RefreshUnconfirmed(recovery))
  }
}

/// Resubmit an unconfirmed publication. The provider is not called; custody
/// returns the published session if it already accepted it.
pub fn recover_refresh(
  client: Client,
  recovery: RefreshRecovery,
) -> Result(Access, SessionError) {
  case recovery.provider == client.provider {
    False -> Error(RefreshRecoveryForeign)
    True -> publish(client, recovery)
  }
}

fn quarantine_name(reason: QuarantineReason) -> String {
  case reason {
    ProviderOutcomeUnknown -> "provider_outcome_unknown"
    RefresherLost -> "refresher_lost"
    ResponseRejected(problem) ->
      "response:"
      <> case problem {
        RefreshedSubjectMismatch -> "subject_mismatch"
        RefreshedIssuerMismatch -> "issuer_mismatch"
        RefreshedAudienceMismatch -> "audience_mismatch"
        RefreshedAuthorizedPartyMismatch -> "authorized_party_mismatch"
        RefreshedNonceMismatch -> "nonce_mismatch"
        RefreshedAuthenticationTimeMismatch -> "authentication_time_mismatch"
        RefreshedScopeChangeUnsupported -> "scope_change"
        RefreshResponseMalformed -> "malformed"
        RefreshedIdTokenInvalid(problem) ->
          "id_token:" <> identity_problem_name(problem)
      }
  }
}

fn quarantine_from(name: String) -> QuarantineReason {
  case name {
    "refresher_lost" -> RefresherLost
    "response:subject_mismatch" -> ResponseRejected(RefreshedSubjectMismatch)
    "response:issuer_mismatch" -> ResponseRejected(RefreshedIssuerMismatch)
    "response:audience_mismatch" -> ResponseRejected(RefreshedAudienceMismatch)
    "response:authorized_party_mismatch" ->
      ResponseRejected(RefreshedAuthorizedPartyMismatch)
    "response:nonce_mismatch" -> ResponseRejected(RefreshedNonceMismatch)
    "response:authentication_time_mismatch" ->
      ResponseRejected(RefreshedAuthenticationTimeMismatch)
    "response:scope_change" -> ResponseRejected(RefreshedScopeChangeUnsupported)
    "response:malformed" -> ResponseRejected(RefreshResponseMalformed)
    "response:id_token:" <> problem ->
      ResponseRejected(
        RefreshedIdTokenInvalid(identity_problem_from_name(problem)),
      )
    _ -> ProviderOutcomeUnknown
  }
}

/// What to do about a session error. An uncertain refresh never maps to a
/// retry of the same request.
pub fn session_error_action(error: SessionError) -> Action {
  case error {
    SessionNotFound | SessionLost | SessionRecordUnreadable -> Reauthenticate
    SessionHasNoAccessToken | RefreshTokenUnavailable | RefreshRevoked ->
      Reauthenticate
    RefreshQuarantined(_) -> Reauthenticate
    SessionForeign | RefreshRecoveryForeign -> FixConfiguration
    RefreshRejected(InvalidClient) | RefreshRejected(UnauthorizedClient) ->
      FixConfiguration
    RefreshRejected(UnsupportedGrantType) -> FixConfiguration
    RefreshRejected(_) -> RetryLater
    SessionStoreUnavailable | RefreshWaitTimedOut -> RetryLater
    RefreshNotSent(_) -> RetryLater
    RefreshUnconfirmed(_) -> Recover
  }
}

pub fn describe_session_error(error: SessionError) -> String {
  case error {
    SessionNotFound -> "no live session has this reference"
    SessionLost -> "the session was lost when in-memory custody restarted"
    SessionForeign -> "the session belongs to another client"
    SessionStoreUnavailable -> "the custody store did not answer"
    SessionRecordUnreadable -> "the stored session did not open"
    SessionHasNoAccessToken -> "the session has no access token"
    RefreshTokenUnavailable ->
      "the access token expired and the session has no refresh token"
    RefreshRevoked -> "the refresh token was rejected (invalid_grant)"
    RefreshRejected(error) ->
      "the token endpoint refused the refresh: " <> oauth_error_name(error)
    RefreshNotSent(failure) ->
      "the refresh was not sent: " <> describe_provider_failure(failure)
    RefreshQuarantined(reason) ->
      "the refresh token is quarantined: " <> quarantine_name(reason)
    RefreshWaitTimedOut ->
      "another request's refresh did not settle in time (with_refresh_wait)"
    RefreshUnconfirmed(_) ->
      "refreshed tokens were not confirmed in custody; call recover_refresh"
    RefreshRecoveryForeign -> "the refresh recovery belongs to another client"
  }
}

// ===========================================================================
// Userinfo

/// Userinfo claims whose `sub` equals the session's subject.
pub opaque type UserInfo {
  UserInfo(subject: String, claims: Redacted(Dynamic))
}

pub fn userinfo_subject(info: UserInfo) -> String {
  info.subject
}

pub fn decode_userinfo(
  info: UserInfo,
  decoder: decode.Decoder(a),
) -> Result(a, List(decode.DecodeError)) {
  decode.run(redacted.reveal(info.claims), decoder)
}

/// May gain variants.
pub type UserinfoError {
  UserinfoSession(SessionError)
  UserinfoNotSupported
  /// The response `sub` differs from the session's subject.
  UserinfoSubjectMismatch
  UserinfoFailed(ProviderFailure)
}

/// The session's userinfo claims, with the access token `access_token`
/// would return (refreshed when near expiry).
pub fn userinfo(
  client: Client,
  session: Session,
) -> Result(UserInfo, UserinfoError) {
  use access <- result.try(
    access_token(client, session) |> result.map_error(UserinfoSession),
  )
  use metadata <- result.try(
    native.metadata(client.backend)
    |> result.map_error(fn(f) { UserinfoFailed(provider_failure(f)) }),
  )
  use _ <- result.try(case metadata.userinfo_endpoint {
    Some(_) -> Ok(Nil)
    None -> Error(UserinfoNotSupported)
  })
  let subject = session.identity.subject
  case
    native.userinfo(
      client.backend,
      access_token: access.token.reveal(),
      expected_subject: subject,
    )
  {
    Ok(claims) ->
      case protocol.string_claim(claims, "sub") {
        Some(value) if value == subject ->
          Ok(UserInfo(subject:, claims: redacted.new(claims)))
        _ -> Error(UserinfoSubjectMismatch)
      }
    Error(protocol.UserinfoSubjectMismatch) -> Error(UserinfoSubjectMismatch)
    Error(failure) -> Error(UserinfoFailed(provider_failure(failure)))
  }
}

pub fn describe_userinfo_error(error: UserinfoError) -> String {
  case error {
    UserinfoSession(error) -> describe_session_error(error)
    UserinfoNotSupported -> "the provider has no userinfo endpoint"
    UserinfoSubjectMismatch -> "the userinfo subject differs from the session's"
    UserinfoFailed(failure) ->
      "userinfo failed: " <> describe_provider_failure(failure)
  }
}

// ===========================================================================
// Client credentials

/// A token for the client itself. Warden does not cache it; call
/// `client_credentials` again near `expires_at`.
pub type ClientToken {
  ClientToken(
    access_token: AccessToken,
    /// When the provider stated a lifetime.
    expires_at: Option(Timestamp),
    scopes: List(String),
  )
}

/// May gain variants.
pub type ClientCredentialsError {
  /// Public clients and resource servers cannot use the grant.
  ClientCredentialsNeedConfidentialClient
  ClientCredentialsInvalidScope(String)
  ClientCredentialsNotSent(ProviderFailure)
  ClientCredentialsRejected(OAuthError)
  /// The request may have reached the provider; its outcome is unknown.
  ClientCredentialsOutcomeUnknown
}

/// Obtain an access token for the client itself (RFC 6749 §4.4).
pub fn client_credentials(
  client: Client,
  scopes: List(String),
) -> Result(ClientToken, ClientCredentialsError) {
  use _ <- result.try(case settings.confidential(client.settings) {
    False -> Error(ClientCredentialsNeedConfidentialClient)
    True -> Ok(Nil)
  })
  use _ <- result.try(
    list.try_each(scopes, fn(scope) {
      case secure.valid_scope(scope) {
        True -> Ok(Nil)
        False -> Error(ClientCredentialsInvalidScope(scope))
      }
    }),
  )
  let now = client.settings.clock()
  case native.client_credentials(client.backend, scopes) {
    Ok(protocol.TokenResponse(access_token: Some(token), ..) as response) ->
      Ok(ClientToken(
        access_token: new_access_token(token, response.token_type),
        expires_at: option.map(response.expires_in, fn(s) {
          timestamp.from_unix_seconds(now + s)
        }),
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

pub fn describe_client_credentials_error(
  error: ClientCredentialsError,
) -> String {
  case error {
    ClientCredentialsNeedConfidentialClient ->
      "client credentials need a confidential client"
    ClientCredentialsInvalidScope(scope) ->
      "the scope " <> string.inspect(scope) <> " is invalid"
    ClientCredentialsNotSent(failure) ->
      "the request was not sent: " <> describe_provider_failure(failure)
    ClientCredentialsRejected(error) ->
      "the token endpoint refused: " <> oauth_error_name(error)
    ClientCredentialsOutcomeUnknown -> "the outcome is unknown"
  }
}

// ===========================================================================
// Introspection

/// The largest token `introspect` sends; a larger one is refused without a
/// request.
pub const max_token_bytes = 8192

pub type Introspection {
  /// The provider reports the token active, and Warden checked `exp`
  /// (strictly) and `nbf` (with the clock tolerance). Introspection does not
  /// itself authorise a resource request: check `audiences` and `scopes`.
  ActiveToken(TokenInfo)
  InactiveToken
}

/// An active token's introspection response (RFC 7662). Read fields by
/// label; decode other claims with `decode_token_claims`.
pub type TokenInfo {
  TokenInfo(
    client_id: Option(String),
    subject: Option(String),
    username: Option(String),
    scopes: List(String),
    /// `aud`, whether the provider sent a string or a list.
    audiences: List(String),
    expires_at: Option(Timestamp),
    issued_at: Option(Timestamp),
    not_before: Option(Timestamp),
    token_type: Option(String),
    issuer: Option(String),
    claims: TokenClaims,
  )
}

/// The full introspection response, held in a closure.
pub opaque type TokenClaims {
  TokenClaims(Redacted(Dynamic))
}

/// Decode the introspection response into a caller-owned type.
pub fn decode_token_claims(
  info: TokenInfo,
  decoder: decode.Decoder(a),
) -> Result(a, List(decode.DecodeError)) {
  let TokenClaims(claims) = info.claims
  decode.run(redacted.reveal(claims), decoder)
}

/// May gain variants.
pub type IntrospectionError {
  /// The provider has no introspection endpoint, or this client has no
  /// credentials to call it with.
  IntrospectionNotSupported
  /// The token is longer than `max_token_bytes`; nothing was sent.
  IntrospectionTokenTooLarge
  IntrospectionFailed(ProviderFailure)
}

/// Ask the provider whether `token` is active (RFC 7662).
pub fn introspect(
  client: Client,
  token: String,
) -> Result(Introspection, IntrospectionError) {
  use _ <- result.try(case client.settings.mode {
    settings.ResourceServer -> Error(IntrospectionNotSupported)
    _ -> Ok(Nil)
  })
  use _ <- result.try(case string.byte_size(token) > max_token_bytes {
    True -> Error(IntrospectionTokenTooLarge)
    False -> Ok(Nil)
  })
  case token {
    "" -> Ok(InactiveToken)
    _ ->
      case native.introspect(client.backend, token) {
        Ok(protocol.Inactive) -> Ok(InactiveToken)
        Ok(protocol.Active(..) as a) -> {
          let now = client.settings.clock()
          let tolerance = client.settings.clock_tolerance_seconds
          let expired = case a.expires_at {
            Some(exp) -> now >= exp
            None -> False
          }
          let early = case a.not_before {
            Some(nbf) -> nbf > now + tolerance
            None -> False
          }
          case expired || early {
            True -> Ok(InactiveToken)
            False ->
              Ok(
                ActiveToken(TokenInfo(
                  client_id: a.client_id,
                  subject: a.subject,
                  username: a.username,
                  scopes: a.scopes,
                  audiences: a.audiences,
                  expires_at: option.map(
                    a.expires_at,
                    timestamp.from_unix_seconds,
                  ),
                  issued_at: option.map(
                    a.issued_at,
                    timestamp.from_unix_seconds,
                  ),
                  not_before: option.map(
                    a.not_before,
                    timestamp.from_unix_seconds,
                  ),
                  token_type: a.token_type,
                  issuer: a.issuer,
                  claims: TokenClaims(redacted.new(a.extra)),
                )),
              )
          }
        }
        Error(protocol.Policy("endpoint_missing")) ->
          Error(IntrospectionNotSupported)
        Error(failure) -> Error(IntrospectionFailed(provider_failure(failure)))
      }
  }
}

pub fn describe_introspection_error(error: IntrospectionError) -> String {
  case error {
    IntrospectionNotSupported -> "introspection is not available"
    IntrospectionTokenTooLarge -> "the token is larger than 8 KiB"
    IntrospectionFailed(failure) ->
      "introspection failed: " <> describe_provider_failure(failure)
  }
}

// ===========================================================================
// Logout

/// Whether `logout` revokes the session's tokens at the provider (RFC 7009).
pub type RevocationPolicy {
  /// Revoke the refresh token, or the access token when the session has no
  /// refresh token. The default.
  RevokeRefreshToken
  SkipRevocation
}

/// Per-logout options. Build from `default_logout()` with record update.
pub type LogoutOptions {
  LogoutOptions(
    /// Must be registered with the provider; validated like redirect URIs.
    post_logout_redirect_uri: Option(String),
    state: Option(String),
    revocation: RevocationPolicy,
  )
}

pub fn default_logout() -> LogoutOptions {
  LogoutOptions(
    post_logout_redirect_uri: None,
    state: None,
    revocation: RevokeRefreshToken,
  )
}

/// The browser redirect to the provider's end-session endpoint. Its URL
/// carries the ID token as `id_token_hint`, so `string.inspect` shows no
/// URL.
pub opaque type LogoutRedirect {
  LogoutRedirect(url: Redacted(String))
}

pub fn logout_url(redirect: LogoutRedirect) -> String {
  redacted.reveal(redirect.url)
}

/// Turn `response` into the redirect: `303 See Other` with `Location` and
/// `Cache-Control: no-store`.
pub fn logout_response(
  response: Response(b),
  redirect: LogoutRedirect,
) -> Response(b) {
  response
  |> response.set_header("location", redacted.reveal(redirect.url))
  |> response.set_header("cache-control", "no-store")
  |> fn(r) { response.Response(..r, status: 303) }
}

/// The session is ended in custody; these report what happened at the
/// provider.
pub type LogoutOutcome {
  LoggedOut(provider_logout: ProviderLogout, revocation: RevocationOutcome)
}

pub type ProviderLogout {
  /// Redirect the browser here to end the provider session (RP-Initiated
  /// Logout).
  RedirectToProvider(LogoutRedirect)
  /// The provider has no end-session endpoint.
  NoEndSessionEndpoint
  /// Provider metadata is unavailable, so no redirect could be built.
  ProviderLogoutUnavailable(ProviderFailure)
}

pub type RevocationOutcome {
  Revoked
  /// The provider has no revocation endpoint.
  RevocationUnsupported
  /// The revocation request failed; custody stays removed.
  RevocationFailed(ProviderFailure)
  RevocationSkipped
}

/// May gain variants.
pub type LogoutError {
  /// `SessionNotFound` (no live session with that reference) or
  /// `SessionForeign`.
  LogoutSession(SessionError)
  InvalidPostLogoutRedirect
  InvalidLogoutState
  /// Custody removal was not confirmed; the session may still exist.
  LogoutStoreUnavailable
}

/// End the session: remove its custody first (by reference, whatever its
/// revision), then revoke its token at the provider (RFC 7009, unless
/// skipped), then build the provider logout redirect with the logout-only
/// ID-token hint. A failed revocation never restores the session.
/// `LogoutSession(SessionNotFound)` reports that no live session had that
/// reference, which callers may treat as signed out.
pub fn logout(
  client: Client,
  session: Session,
  options: LogoutOptions,
) -> Result(LogoutOutcome, LogoutError) {
  let started = secure.monotonic_ms()
  use _ <- result.try(case options.post_logout_redirect_uri {
    Some(uri) ->
      case secure.valid_redirect_uri(uri) {
        True -> Ok(Nil)
        False -> Error(InvalidPostLogoutRedirect)
      }
    None -> Ok(Nil)
  })
  use _ <- result.try(case options.state {
    Some(state) ->
      case state != "" && secure.printable(state) {
        True -> Ok(Nil)
        False -> Error(InvalidLogoutState)
      }
    None -> Ok(Nil)
  })
  use _ <- result.try(case session.provider == client.provider {
    True -> Ok(Nil)
    False -> Error(LogoutSession(SessionForeign))
  })
  // Removal is by reference, not revision: a refresh that raced this logout
  // must not keep the session alive. The removed snapshot carries the
  // latest tokens for revocation and the hint.
  use snapshot <- result.try(
    case
      custody.remove(
        client.custody,
        redacted.reveal(session.reference),
        client.provider,
      )
    {
      custody.RemovalFailed -> Error(LogoutStoreUnavailable)
      custody.RemovalMissing -> Error(LogoutSession(SessionNotFound))
      custody.RemovalForeign -> Error(LogoutSession(SessionForeign))
      custody.Removed(snapshot) -> Ok(snapshot)
    },
  )
  let tokens = snapshot.entry.tokens
  let revocation = case options.revocation {
    SkipRevocation -> RevocationSkipped
    RevokeRefreshToken ->
      case tokens.refresh_token, tokens.access_token {
        None, "" -> RevocationSkipped
        refresh_token, access_token -> {
          let #(token, hint) = case refresh_token {
            Some(token) -> #(token, "refresh_token")
            None -> #(access_token, "access_token")
          }
          case native.revoke(client.backend, token:, hint:) {
            Ok(Nil) -> Revoked
            Error(protocol.Policy("endpoint_missing")) -> RevocationUnsupported
            Error(failure) -> RevocationFailed(provider_failure(failure))
          }
        }
      }
  }
  let provider_logout = case native.metadata(client.backend) {
    Error(failure) -> ProviderLogoutUnavailable(provider_failure(failure))
    Ok(metadata) ->
      case metadata.end_session_endpoint {
        None -> NoEndSessionEndpoint
        Some(_) ->
          case
            native.logout_url(
              client.backend,
              id_token_hint: tokens.id_token,
              post_logout_redirect_uri: options.post_logout_redirect_uri,
              state: options.state,
            )
          {
            Ok(url) -> RedirectToProvider(LogoutRedirect(redacted.new(url)))
            Error(failure) ->
              ProviderLogoutUnavailable(provider_failure(failure))
          }
      }
  }
  sinal.emit(
    telemetry.logout(),
    telemetry.SessionMeasurements(duration_ms: secure.monotonic_ms() - started),
    telemetry.Logout(
      revocation: case revocation {
        Revoked -> telemetry.Revoked
        RevocationUnsupported -> telemetry.RevocationUnsupported
        RevocationFailed(_) -> telemetry.RevocationFailed
        RevocationSkipped -> telemetry.RevocationSkipped
      },
      correlation: client.correlation,
    ),
  )
  Ok(LoggedOut(provider_logout:, revocation:))
}

pub fn describe_logout_error(error: LogoutError) -> String {
  case error {
    LogoutSession(error) -> describe_session_error(error)
    InvalidPostLogoutRedirect -> "the post-logout redirect URI is invalid"
    InvalidLogoutState -> "the logout state is empty or not printable"
    LogoutStoreUnavailable ->
      "custody did not confirm the removal; the session may still exist"
  }
}

// ===========================================================================
// Shared helpers

fn provider_failure(failure: protocol.Failure) -> ProviderFailure {
  case failure {
    protocol.NotReady -> ProviderNotReady
    protocol.Transport(sent:, class:) ->
      TransportFailure(
        evidence: case sent {
          True -> MaybeSent
          False -> NotSent
        },
        reason: transport_reason(class),
      )
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
    "receive_failed" -> ReceiveFailed
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
