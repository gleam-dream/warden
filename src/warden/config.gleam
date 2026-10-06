//// Warden configuration: an opaque `Config` built from one constructor and
//// `with_*` setters. Nothing here opens a connection or starts a process;
//// `warden.new` validates the configuration and `warden.start` discovers the
//// provider.
////
//// ```gleam
//// let config =
////   config.new(
////     issuer: "https://login.example.com",
////     client_id: "app",
////     redirect_uri: "https://app.example.com/auth/callback",
////     authentication: config.ClientSecretBasic(config.secret(client_secret)),
////   )
////   |> config.with_scopes(["profile", "email"])
//// let assert Ok(client) = warden.new(config)
//// ```
////
//// Three constructors cover the three roles:
////
//// - `new`: a relying party that signs users in (and may do everything
////   else);
//// - `service_client`: a confidential client with no login: client
////   credentials, introspection and access-token validation;
//// - `resource_server`: access-token validation only (`warden/resource`),
////   with no client identity.
////
//// ## Defaults
////
//// | Setting | Default | Setter |
//// | --- | --- | --- |
//// | redirect URI | the one given to `new` | `with_allowed_redirect_uris` (exact match) |
//// | scopes | `openid` | `with_scopes` |
//// | ID-token algorithms | RS256, PS256, ES256, EdDSA (`none` and HMAC unrepresentable) | `with_signing_algorithms` |
//// | response mode | query | `with_response_mode` |
//// | RFC 9207 `iss` | required when advertised | `with_issuer_parameter` |
//// | PKCE | advertised S256 required | `with_pkce_advertisement` |
//// | TLS trust | system CA store | `with_trust` |
//// | destinations | public addresses only | `with_destinations`, `with_allowed_hosts` |
//// | provider request | 10 s | `with_request_timeout` |
//// | provider response body | 1 MiB | `with_max_response_bytes` |
//// | startup discovery, keys and previous-process cleanup | 15 s | `with_startup_timeout` |
//// | store call | 5 s | `with_store_timeout` |
//// | `complete_login`, end to end | 30 s | `with_login_timeout` |
//// | pending login | 10 min | `with_login_lifetime` |
//// | pending logins in the built-in store | 100 000 | `with_max_pending_logins` |
//// | session | 12 h absolute, 1 h idle | `with_session_lifetime` |
//// | clock tolerance (`iat`, `nbf`, `auth_time`; never `exp`) | 5 s | `with_clock_tolerance` |
//// | refresh before expiry | 30 s | `with_refresh_margin` |
//// | wait for another request's refresh | 5 s | `with_refresh_wait` |
//// | session and login storage | in memory | `with_custody_store`, `with_transaction_store` |
////
//// Secrets (`Secret`, `SigningKey`, `SealingKey`) are held in closures, so
//// `string.inspect` of a configuration prints no credential.

import exception
import gleam/bit_array
import gleam/dict
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/erlang/atom
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/time/duration.{type Duration}
import gleam/uri
import gose
import gose/jose/jwk
import kryptos/ec
import kryptos/eddsa
import warden/internal/key_policy
import warden/internal/redacted
import warden/internal/secure
import warden/internal/settings.{type Settings, Settings}
import warden/store.{type Store}

/// A Warden configuration. Build it with `new`, `service_client` or
/// `resource_server` and the `with_*` setters.
pub type Config =
  Settings

// ---------------------------------------------------------------------------
// Secret material

/// A client secret, held in a closure: `string.inspect` and logs of a
/// configuration show no secret. This does not protect against VM inspection
/// or crash dumps; see docs/APPLICATION-RESPONSIBILITIES.md.
pub opaque type Secret {
  Secret(reveal: fn() -> String)
}

/// Wrap a client secret.
pub fn secret(value: String) -> Secret {
  Secret(reveal: fn() { value })
}

/// A private signing key for `private_key_jwt`, held like `Secret`.
pub opaque type SigningKey {
  SigningKey(
    reveal: fn() -> String,
    key_id: Option(String),
    algorithms: List(String),
  )
}

pub type SigningKeyError {
  /// The text is not a JSON Web Key with private signing material.
  NotAPrivateSigningJwk
  /// An RSA key below 2048 bits (RFC 7518 §3.3).
  WeakRsaKey
  /// The key's `use` or `key_ops` does not permit signing.
  NotForSigning
}

/// Parse a private JSON Web Key (RSA, EC P-256/384/521 or Ed25519).
pub fn signing_key_from_jwk(
  json: String,
) -> Result(SigningKey, SigningKeyError) {
  case jwk.from_json(json) {
    Ok(key) ->
      case gose.is_private_key(key), jwk_fields(json) {
        False, _ -> Error(NotAPrivateSigningJwk)
        True, fields -> {
          use _ <- result.try(case key_policy.strong_enough(fields) {
            True -> Ok(Nil)
            False -> Error(WeakRsaKey)
          })
          use _ <- result.try(case key_policy.for_signing(fields) {
            True -> Ok(Nil)
            False -> Error(NotForSigning)
          })
          let algorithms = case gose.key_type(key) {
            gose.RsaKeyType -> ["RS256", "PS256"]
            gose.EcKeyType ->
              case gose.ec_curve(key) {
                Ok(ec.P256) -> ["ES256"]
                Ok(ec.P384) -> ["ES384"]
                Ok(ec.P521) -> ["ES512"]
                _ -> []
              }
            gose.OkpKeyType ->
              case gose.eddsa_curve(key) {
                Ok(eddsa.Ed25519) -> ["EdDSA"]
                _ -> []
              }
            gose.OctKeyType -> []
          }
          // A JWK `alg` member restricts the key to that algorithm.
          let algorithms = case gose.alg(key) {
            Ok(alg) ->
              list.filter(algorithms, fn(a) { a == jwk.alg_to_string(alg) })
            Error(Nil) -> algorithms
          }
          Ok(SigningKey(
            reveal: fn() { json },
            key_id: option.from_result(gose.kid(key)),
            algorithms:,
          ))
        }
      }
    Error(_) -> Error(NotAPrivateSigningJwk)
  }
}

fn jwk_fields(text: String) -> dict.Dict(String, Dynamic) {
  json.parse(text, decode.dict(decode.string, decode.dynamic))
  |> result.unwrap(dict.new())
}

/// The key that seals records in a durable store (`with_sealing_key`): 32
/// random bytes, held in a closure. Generate one with
/// `crypto.strong_random_bytes(32)` and keep it in a secret manager.
pub opaque type SealingKey {
  SealingKey(reveal: fn() -> BitArray)
}

pub type SealingKeyError {
  /// A sealing key must be exactly 32 bytes (AES-256).
  SealingKeyNot32Bytes
}

/// A sealing key from 32 bytes.
pub fn sealing_key(bytes: BitArray) -> Result(SealingKey, SealingKeyError) {
  case bit_array.byte_size(bytes) {
    32 -> Ok(SealingKey(reveal: fn() { bytes }))
    _ -> Error(SealingKeyNot32Bytes)
  }
}

// ---------------------------------------------------------------------------
// Public option types

/// How the client authenticates at the token, introspection and revocation
/// endpoints. Warden uses exactly this method; it never falls back to
/// another method the provider advertises. May gain variants (mTLS).
pub type ClientAuthentication {
  /// A public client. PKCE still applies; no client secret is sent.
  PublicClient
  ClientSecretBasic(Secret)
  ClientSecretPost(Secret)
  /// HMAC-signed client assertion (RFC 7523) using the client secret.
  ClientSecretJwt(Secret)
  /// Client assertion signed with the client's private key.
  PrivateKeyJwt(SigningKey)
}

/// ID-token and access-token signing algorithms Warden accepts. `none` and
/// HMAC algorithms are not representable; the provider's advertised list is
/// intersected with this allowlist.
pub type SigningAlgorithm {
  Rs256
  Rs384
  Rs512
  Ps256
  Ps384
  Ps512
  Es256
  Es384
  Es512
  EdDsa
}

/// How the provider returns the authorization response. May gain JARM.
pub type ResponseMode {
  /// Redirect with a query string (the OAuth default).
  Query
  /// Cross-site POST of an HTML form (OAuth 2.0 Form Post Response Mode).
  FormPost
}

/// RFC 9207 `iss` authorization-response parameter policy. A present `iss`
/// must always equal the configured issuer.
pub type IssuerParameterPolicy {
  /// Require `iss` when the provider advertises
  /// `authorization_response_iss_parameter_supported`.
  RequireIssuerWhenAdvertised
  /// Always require `iss`.
  AlwaysRequireIssuer
}

/// How Warden establishes that the provider supports PKCE `S256`
/// (RFC 9700 §2.1.1). Warden always sends an `S256` challenge and its
/// verifier; this policy only decides which providers it accepts.
pub type PkceAdvertisementPolicy {
  /// The provider must list `S256` in `code_challenge_methods_supported`.
  RequireAdvertisedS256
  /// Also accept a provider whose metadata omits
  /// `code_challenge_methods_supported` entirely. A provider that lists the
  /// field without `S256` is still refused. Refused for public clients.
  AssumeS256WhenUnadvertised
}

/// Trust anchors for provider TLS.
pub type Trust {
  /// The operating system's trust store.
  SystemTrust
  /// Only the certificates in this PEM text.
  TrustAnchorsPem(String)
}

/// Which network destinations provider requests may reach. Every resolved
/// address must satisfy the policy.
pub type DestinationPolicy {
  /// Public unicast addresses only.
  PublicInternetOnly
  /// Also loopback addresses. For local test providers only.
  AllowLoopbackForTesting
  /// Also private (RFC 1918, unique-local, shared) addresses, for providers
  /// inside a private network. Loopback stays rejected.
  AllowPrivateNetwork
}

// ---------------------------------------------------------------------------
// Constructors

/// A relying party that signs users in, with Warden's defaults (see the
/// module documentation).
pub fn new(
  issuer issuer: String,
  client_id client_id: String,
  redirect_uri redirect_uri: String,
  authentication authentication: ClientAuthentication,
) -> Config {
  base(settings.RelyingParty, issuer, client_id, authentication)
  |> fn(s) { Settings(..s, redirect_uri:) }
}

/// A confidential client without login: client credentials, introspection
/// and access-token validation. It needs no redirect URI, and `warden.start`
/// does not require the provider to support the authorization code flow.
/// `begin_login` and `complete_login` answer `LoginNotConfigured`. A
/// `PublicClient` is refused by validation.
pub fn service_client(
  issuer issuer: String,
  client_id client_id: String,
  authentication authentication: ClientAuthentication,
) -> Config {
  base(settings.ServiceClient, issuer, client_id, authentication)
  |> fn(s) {
    Settings(..s, service_without_credentials: authentication == PublicClient)
  }
}

/// A resource server that only validates access tokens locally
/// (`warden/resource`) against the issuer's published keys. It has no
/// client identity: login, client credentials and introspection are not
/// available.
pub fn resource_server(issuer issuer: String) -> Config {
  base(settings.ResourceServer, issuer, "", PublicClient)
}

fn base(
  mode: settings.Mode,
  issuer: String,
  client_id: String,
  authentication: ClientAuthentication,
) -> Settings {
  Settings(
    mode:,
    issuer:,
    client_id:,
    redirect_uri: "",
    allowed_redirect_uris: [],
    authentication: to_authentication(authentication),
    service_without_credentials: False,
    scopes: [],
    signing_algorithms: ["RS256", "PS256", "ES256", "EdDSA"],
    response_mode: settings.Query,
    always_require_issuer: False,
    assume_s256: False,
    trust: settings.SystemTrust,
    destinations: settings.PublicOnly,
    allowed_hosts: None,
    request_timeout_ms: 10_000,
    max_response_bytes: 1_048_576,
    startup_timeout_ms: 15_000,
    store_timeout_ms: 5000,
    login_timeout_ms: 30_000,
    login_lifetime_seconds: 600,
    max_pending_logins: 100_000,
    session_absolute_seconds: 43_200,
    session_idle_seconds: 3600,
    clock_tolerance_seconds: 5,
    refresh_margin_seconds: 30,
    refresh_wait_ms: 5000,
    custody_store: None,
    transaction_store: None,
    sealing_key: None,
    previous_sealing_keys: [],
    clock: secure.now_seconds,
  )
}

fn to_authentication(
  authentication: ClientAuthentication,
) -> settings.Authentication {
  case authentication {
    PublicClient -> settings.NoClientAuthentication
    ClientSecretBasic(s) ->
      settings.SharedSecret("client_secret_basic", redacted.new(s.reveal()))
    ClientSecretPost(s) ->
      settings.SharedSecret("client_secret_post", redacted.new(s.reveal()))
    ClientSecretJwt(s) ->
      settings.SharedSecret("client_secret_jwt", redacted.new(s.reveal()))
    PrivateKeyJwt(key) ->
      settings.PrivateKey(
        jwk: redacted.new(key.reveal()),
        key_id: key.key_id,
        algorithms: key.algorithms,
      )
  }
}

// ---------------------------------------------------------------------------
// Setters

/// Further redirect URIs a login may choose with
/// `warden.LoginOptions(redirect_uri: Some(uri), ..)`, for an application
/// served under several registered callback addresses. The URI given to
/// `new` stays the default and is always allowed.
///
/// A login's URI must equal one of these strings exactly: no prefix,
/// wildcard, port, case or percent-encoding normalisation. Anything else
/// fails the login with `InvalidLoginOption(RedirectUriNotAllowed)`. Each
/// URI must also be registered at the provider. Only a relying party
/// (`new`) takes them.
pub fn with_allowed_redirect_uris(
  config: Config,
  uris: List(String),
) -> Config {
  Settings(..config, allowed_redirect_uris: list.unique(uris))
}

/// Scopes requested at every login, in addition to `openid`.
pub fn with_scopes(config: Config, scopes: List(String)) -> Config {
  Settings(
    ..config,
    scopes: list.filter(scopes, fn(s) { s != "openid" }) |> list.unique,
  )
}

pub fn with_response_mode(config: Config, mode: ResponseMode) -> Config {
  Settings(..config, response_mode: case mode {
    Query -> settings.Query
    FormPost -> settings.FormPost
  })
}

/// The ID-token and access-token algorithms Warden accepts.
pub fn with_signing_algorithms(
  config: Config,
  algorithms: List(SigningAlgorithm),
) -> Config {
  Settings(
    ..config,
    signing_algorithms: list.map(algorithms, algorithm_name) |> list.unique,
  )
}

pub fn with_trust(config: Config, trust: Trust) -> Config {
  Settings(..config, trust: case trust {
    SystemTrust -> settings.SystemTrust
    TrustAnchorsPem(pem) ->
      case pem_certificates(pem) {
        Ok(ders) -> settings.Anchors(ders)
        Error(Nil) -> settings.UnreadableAnchors
      }
  })
}

pub fn with_destinations(config: Config, policy: DestinationPolicy) -> Config {
  Settings(..config, destinations: case policy {
    PublicInternetOnly -> settings.PublicOnly
    AllowLoopbackForTesting -> settings.AllowLoopback
    AllowPrivateNetwork -> settings.AllowPrivate
  })
}

/// Provider requests may reach only these host names (case-insensitive).
pub fn with_allowed_hosts(config: Config, hosts: List(String)) -> Config {
  Settings(..config, allowed_hosts: Some(list.map(hosts, string.lowercase)))
}

/// Deadline for one provider request, including connection setup. Between
/// 1 ms and 5 minutes; default 10 s.
pub fn with_request_timeout(config: Config, timeout: Duration) -> Config {
  Settings(..config, request_timeout_ms: duration.to_milliseconds(timeout))
}

/// Largest provider response body. Between 1 KiB and 64 MiB; default 1 MiB.
pub fn with_max_response_bytes(config: Config, bytes: Int) -> Config {
  Settings(..config, max_response_bytes: bytes)
}

/// One deadline for `warden.start` discovery, first keys and joining any
/// previous client processes. Supervised startup uses the same bound when
/// joining a previous tree; its background discovery retries independently.
/// Between 1 ms and 10 minutes; default 15 s.
pub fn with_startup_timeout(config: Config, timeout: Duration) -> Config {
  Settings(..config, startup_timeout_ms: duration.to_milliseconds(timeout))
}

/// Bound on one store call. Between 1 ms and 10 minutes; default 5 s.
pub fn with_store_timeout(config: Config, timeout: Duration) -> Config {
  Settings(..config, store_timeout_ms: duration.to_milliseconds(timeout))
}

/// One bound on `complete_login`: store calls, the code exchange, key
/// refreshes and custody installation together. Between 1 ms and 10
/// minutes; default 30 s.
pub fn with_login_timeout(config: Config, timeout: Duration) -> Config {
  Settings(..config, login_timeout_ms: duration.to_milliseconds(timeout))
}

/// How long a pending login waits for its callback. Between 1 s and 1 day;
/// default 10 minutes.
pub fn with_login_lifetime(config: Config, lifetime: Duration) -> Config {
  Settings(..config, login_lifetime_seconds: whole_seconds(lifetime))
}

/// Capacity of the built-in in-memory login store, counting pending logins
/// and recently completed ones (kept to detect replays). A full store
/// answers `TooManyPendingLogins`. Between 1 and 10 000 000; default
/// 100 000. A durable store enforces its own capacity (`store.StoreFull`).
pub fn with_max_pending_logins(config: Config, count: Int) -> Config {
  Settings(..config, max_pending_logins: count)
}

/// How long a session lasts in custody: `absolute` after login at most, and
/// `idle` without use (restore, access token, userinfo, refresh). Expired
/// sessions are removed with their tokens. Defaults: 12 hours absolute, 1
/// hour idle; idle must not exceed absolute, and absolute is at most a year.
/// The number of sessions per identity is not bounded.
pub fn with_session_lifetime(
  config: Config,
  absolute absolute: Duration,
  idle idle: Duration,
) -> Config {
  Settings(
    ..config,
    session_absolute_seconds: whole_seconds(absolute),
    session_idle_seconds: whole_seconds(idle),
  )
}

/// How far a provider's clock may run ahead of this node for `iat`, `nbf`
/// and `auth_time`; `exp` never gets tolerance. Default 5 s, at most 300 s.
pub fn with_clock_tolerance(config: Config, tolerance: Duration) -> Config {
  Settings(..config, clock_tolerance_seconds: whole_seconds(tolerance))
}

/// `warden.access_token` refreshes a token that expires within this margin.
/// Between 0 and 1 hour; default 30 s.
pub fn with_refresh_margin(config: Config, margin: Duration) -> Config {
  Settings(..config, refresh_margin_seconds: whole_seconds(margin))
}

/// How long a request waits for another request's refresh of the same
/// session before answering `RefreshWaitTimedOut`. Between 0 and 1 minute;
/// default 5 s.
pub fn with_refresh_wait(config: Config, wait: Duration) -> Config {
  Settings(..config, refresh_wait_ms: duration.to_milliseconds(wait))
}

pub fn with_pkce_advertisement(
  config: Config,
  policy: PkceAdvertisementPolicy,
) -> Config {
  Settings(..config, assume_s256: policy == AssumeS256WhenUnadvertised)
}

pub fn with_issuer_parameter(
  config: Config,
  policy: IssuerParameterPolicy,
) -> Config {
  Settings(..config, always_require_issuer: policy == AlwaysRequireIssuer)
}

/// Keep sessions in this store instead of memory. Needs `with_sealing_key`.
pub fn with_custody_store(config: Config, store: Store) -> Config {
  Settings(..config, custody_store: Some(store))
}

/// Keep pending logins in this store instead of memory, so a callback may
/// reach another node. Needs `with_sealing_key`.
pub fn with_transaction_store(config: Config, store: Store) -> Config {
  Settings(..config, transaction_store: Some(store))
}

/// The key that seals records in durable stores. New records are sealed with
/// it; records sealed with a key passed to `with_previous_sealing_keys` are
/// still read, so a key can be rotated without signing users out.
pub fn with_sealing_key(config: Config, key: SealingKey) -> Config {
  Settings(..config, sealing_key: Some(redacted.new(key.reveal())))
}

/// Retired sealing keys that may still have sealed stored records.
pub fn with_previous_sealing_keys(
  config: Config,
  keys: List(SealingKey),
) -> Config {
  Settings(
    ..config,
    previous_sealing_keys: list.map(keys, fn(key) { redacted.new(key.reveal()) }),
  )
}

fn whole_seconds(value: Duration) -> Int {
  let #(seconds, _) = duration.to_seconds_and_nanoseconds(value)
  seconds
}

// ---------------------------------------------------------------------------
// Validation

/// A bounded setting, as `InvalidLimit` names it.
pub type Limit {
  RequestTimeout
  MaxResponseBytes
  StartupTimeout
  StoreTimeout
  LoginTimeout
  LoginLifetime
  MaxPendingLogins
  SessionLifetime
  ClockTolerance
  RefreshMargin
  RefreshWait
}

/// Why a configuration is invalid. May gain variants.
pub type ConfigError {
  /// The issuer must be an absolute `https` URI without query or fragment.
  InvalidIssuer
  InvalidClientId
  /// The redirect URI must be absolute, without fragment, and `https` unless
  /// its host is a loopback address or `localhost`.
  InvalidRedirectUri
  /// A URI given to `with_allowed_redirect_uris` breaks the redirect URI
  /// rule above.
  InvalidAllowedRedirectUri(String)
  /// `with_allowed_redirect_uris` on a `service_client` or
  /// `resource_server`, which have no login.
  AllowedRedirectUrisNeedLogin
  /// A scope token contains a byte outside RFC 6749 §3.3 or is empty.
  InvalidScope(String)
  NoSigningAlgorithms
  /// The signing key cannot produce any assertion algorithm.
  SigningKeyUnusable
  InvalidTrustAnchors
  InvalidAllowedHost(String)
  /// A numeric setting is out of range; `describe_config_error` names the
  /// range and the setter.
  InvalidLimit(Limit)
  /// `AssumeS256WhenUnadvertised` with `PublicClient`.
  UnadvertisedPkceRequiresConfidentialClient
  /// A client secret is empty.
  EmptyClientSecret
  /// A `client_secret_jwt` secret is shorter than 32 bytes, the minimum HMAC
  /// key for HS256 (RFC 7518 §3.2).
  ClientSecretTooShort
  /// `service_client` with `PublicClient`: a service authenticates itself.
  ServiceClientNeedsCredentials
  /// A durable store is configured without `with_sealing_key`.
  SealingKeyRequired
}

/// Check a configuration without starting anything. Returns every problem
/// found; `warden.new` runs the same check.
pub fn validate(config: Config) -> Result(Nil, List(ConfigError)) {
  let relying_party = config.mode == settings.RelyingParty
  let checks = [
    check(valid_issuer(config.issuer), InvalidIssuer),
    check(
      config.mode == settings.ResourceServer
        || config.client_id != ""
        && string.length(config.client_id) <= 512,
      InvalidClientId,
    ),
    check(
      !relying_party || valid_redirect_uri(config.redirect_uri),
      InvalidRedirectUri,
    ),
    check(
      relying_party || config.allowed_redirect_uris == [],
      AllowedRedirectUrisNeedLogin,
    ),
    check(config.signing_algorithms != [], NoSigningAlgorithms),
    check(
      case config.authentication {
        settings.PrivateKey(algorithms:, ..) -> algorithms != []
        _ -> True
      },
      SigningKeyUnusable,
    ),
    check(config.trust != settings.UnreadableAnchors, InvalidTrustAnchors),
    limit(config.request_timeout_ms, 1, 300_000, RequestTimeout),
    limit(config.max_response_bytes, 1024, 67_108_864, MaxResponseBytes),
    limit(config.startup_timeout_ms, 1, 600_000, StartupTimeout),
    limit(config.store_timeout_ms, 1, 600_000, StoreTimeout),
    limit(config.login_timeout_ms, 1, 600_000, LoginTimeout),
    limit(config.login_lifetime_seconds, 1, 86_400, LoginLifetime),
    limit(config.max_pending_logins, 1, 10_000_000, MaxPendingLogins),
    limit(config.clock_tolerance_seconds, 0, 300, ClockTolerance),
    limit(config.refresh_margin_seconds, 0, 3600, RefreshMargin),
    limit(config.refresh_wait_ms, 0, 60_000, RefreshWait),
    check(
      config.session_idle_seconds > 0
        && config.session_idle_seconds <= config.session_absolute_seconds
        && config.session_absolute_seconds <= 31_536_000,
      InvalidLimit(SessionLifetime),
    ),
    check(
      !config.assume_s256 || settings.confidential(config),
      UnadvertisedPkceRequiresConfidentialClient,
    ),
    check(!config.service_without_credentials, ServiceClientNeedsCredentials),
    check(
      case config.authentication {
        settings.SharedSecret(secret:, ..) -> redacted.reveal(secret) != ""
        _ -> True
      },
      EmptyClientSecret,
    ),
    check(
      case config.authentication {
        settings.SharedSecret(method: "client_secret_jwt", secret:) -> {
          let size = string.byte_size(redacted.reveal(secret))
          size == 0 || size >= settings.hmac_key_bytes("HS256")
        }
        _ -> True
      },
      ClientSecretTooShort,
    ),
    check(
      config.sealing_key != None
        || config.custody_store == None
        && config.transaction_store == None,
      SealingKeyRequired,
    ),
  ]
  let scope_errors =
    config.scopes
    |> list.filter(fn(scope) { !valid_scope(scope) })
    |> list.map(InvalidScope)
  let redirect_errors =
    config.allowed_redirect_uris
    |> list.filter(fn(uri) { !valid_redirect_uri(uri) })
    |> list.map(InvalidAllowedRedirectUri)
  let host_errors = case config.allowed_hosts {
    None -> []
    Some(hosts) ->
      hosts
      |> list.filter(fn(host) { !valid_host(host) })
      |> list.map(InvalidAllowedHost)
  }
  case
    list.flatten([
      option.values(checks),
      redirect_errors,
      scope_errors,
      host_errors,
    ])
  {
    [] -> Ok(Nil)
    errors -> Error(errors)
  }
}

fn check(condition: Bool, error: ConfigError) -> Option(ConfigError) {
  case condition {
    True -> None
    False -> Some(error)
  }
}

fn limit(value: Int, low: Int, high: Int, which: Limit) -> Option(ConfigError) {
  check(value >= low && value <= high, InvalidLimit(which))
}

/// Describe a configuration error for logs, naming the setter to change.
pub fn describe_config_error(error: ConfigError) -> String {
  case error {
    InvalidIssuer ->
      "the issuer must be an absolute https URI without query or fragment"
    InvalidClientId -> "the client id must be 1 to 512 characters"
    InvalidRedirectUri ->
      "the redirect URI must be absolute, without fragment, and https unless its host is loopback"
    InvalidAllowedRedirectUri(uri) ->
      "the allowed redirect URI "
      <> string.inspect(uri)
      <> " must be absolute, without fragment, and https unless its host is loopback"
    AllowedRedirectUrisNeedLogin ->
      "with_allowed_redirect_uris needs a relying party (config.new)"
    InvalidScope(scope) ->
      "the scope " <> string.inspect(scope) <> " is not an RFC 6749 scope token"
    NoSigningAlgorithms ->
      "with_signing_algorithms needs at least one algorithm"
    SigningKeyUnusable ->
      "the private key supports no client-assertion algorithm"
    InvalidTrustAnchors ->
      "the PEM text given to with_trust holds no readable certificate, or another block"
    InvalidAllowedHost(host) ->
      "the allowed host " <> string.inspect(host) <> " is not a host name"
    InvalidLimit(which) -> describe_limit(which)
    UnadvertisedPkceRequiresConfidentialClient ->
      "AssumeS256WhenUnadvertised needs a confidential client"
    EmptyClientSecret -> "the client secret is empty"
    ClientSecretTooShort ->
      "a client_secret_jwt secret must be at least 32 bytes"
    ServiceClientNeedsCredentials ->
      "service_client needs client authentication, not PublicClient"
    SealingKeyRequired -> "a durable store needs with_sealing_key"
  }
}

fn describe_limit(which: Limit) -> String {
  case which {
    RequestTimeout -> "with_request_timeout must be between 1 ms and 5 minutes"
    MaxResponseBytes ->
      "with_max_response_bytes must be between 1 KiB and 64 MiB"
    StartupTimeout -> "with_startup_timeout must be between 1 ms and 10 minutes"
    StoreTimeout -> "with_store_timeout must be between 1 ms and 10 minutes"
    LoginTimeout -> "with_login_timeout must be between 1 ms and 10 minutes"
    LoginLifetime -> "with_login_lifetime must be between 1 s and 1 day"
    MaxPendingLogins ->
      "with_max_pending_logins must be between 1 and 10 000 000"
    SessionLifetime ->
      "with_session_lifetime needs 0 < idle <= absolute <= 1 year (whole seconds)"
    ClockTolerance -> "with_clock_tolerance must be between 0 and 300 s"
    RefreshMargin -> "with_refresh_margin must be between 0 and 1 hour"
    RefreshWait -> "with_refresh_wait must be between 0 and 1 minute"
  }
}

/// RFC 6749 §3.3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E ).
fn valid_scope(scope: String) -> Bool {
  secure.valid_scope(scope)
}

fn valid_issuer(issuer: String) -> Bool {
  case uri.parse(issuer) {
    Ok(uri.Uri(
      scheme: Some("https"),
      userinfo: None,
      host: Some(host),
      query: None,
      fragment: None,
      ..,
    )) ->
      host != ""
      && !string.contains(issuer, "#")
      && !string.contains(issuer, "?")
    _ -> False
  }
}

fn valid_redirect_uri(redirect: String) -> Bool {
  secure.valid_redirect_uri(redirect)
}

fn valid_host(host: String) -> Bool {
  host != "" && !string.contains(host, "/") && !string.contains(host, ":")
}

fn algorithm_name(algorithm: SigningAlgorithm) -> String {
  case algorithm {
    Rs256 -> "RS256"
    Rs384 -> "RS384"
    Rs512 -> "RS512"
    Ps256 -> "PS256"
    Ps384 -> "PS384"
    Ps512 -> "PS512"
    Es256 -> "ES256"
    Es384 -> "ES384"
    Es512 -> "ES512"
    EdDsa -> "EdDSA"
  }
}

/// DER certificates from PEM text. Every block must be an X.509
/// certificate that decodes; any other block (a private key, a corrupt
/// certificate) rejects the whole input, as does an input with none.
fn pem_certificates(pem: String) -> Result(List(BitArray), Nil) {
  let entry = {
    use kind <- decode.field(0, atom.decoder())
    use der <- decode.field(1, decode.bit_array)
    decode.success(#(atom.to_string(kind), der))
  }
  use entries <- result.try(
    exception.rescue(fn() { pem_decode(<<pem:utf8>>) })
    |> result.replace_error(Nil),
  )
  use entries <- result.try(
    decode.run(entries, decode.list(entry)) |> result.replace_error(Nil),
  )
  use ders <- result.try(
    list.try_map(entries, fn(entry) {
      case entry {
        #("Certificate", der) ->
          case
            exception.rescue(fn() { pkix_decode_cert(der, atom.create("otp")) })
          {
            Ok(_) -> Ok(der)
            Error(_) -> Error(Nil)
          }
        _ -> Error(Nil)
      }
    }),
  )
  case ders {
    [] -> Error(Nil)
    _ -> Ok(ders)
  }
}

@external(erlang, "public_key", "pem_decode")
fn pem_decode(pem: BitArray) -> Dynamic

@external(erlang, "public_key", "pkix_decode_cert")
fn pkix_decode_cert(der: BitArray, form: atom.Atom) -> Dynamic
