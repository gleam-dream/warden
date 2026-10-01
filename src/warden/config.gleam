//// Pure Warden configuration.
////
//// Build a `Settings` value with `new` and the `with_*` functions, then call
//// `validate` to obtain a `Config`. Nothing here opens a connection, starts a
//// process or reads the clock; `warden.start` performs discovery with a
//// validated `Config`.
////
//// ```gleam
//// let settings =
////   config.new(
////     issuer: "https://login.example.com",
////     client_id: "app",
////     redirect_uri: "https://app.example.com/auth/callback",
////     authentication: config.ClientSecretBasic(config.secret(client_secret)),
////   )
////   |> config.with_scopes(["profile", "email"])
//// let assert Ok(validated) = config.validate(settings)
//// ```

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
import gleam/uri
import gose
import gose/jose/jwk
import kryptos/ec
import kryptos/eddsa
import warden/internal/key_policy
import warden/internal/transport

// ---------------------------------------------------------------------------
// Secret material

/// A client secret. The value is held in a closure, so `string.inspect` and
/// ordinary logging of configuration show no secret. This does not protect
/// against VM inspection or crash dumps; see the operational notes.
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

// ---------------------------------------------------------------------------
// Settings

/// How the client authenticates at the token, introspection and other
/// endpoints. Warden uses exactly this method; it never falls back to another
/// method advertised by the provider.
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

/// ID-token signing algorithms Warden accepts. `none` and HMAC algorithms are
/// not representable; the provider's advertised list is intersected with this
/// allowlist.
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

/// How the provider returns the authorization response.
pub type ResponseMode {
  /// Redirect with a query string (the OAuth default).
  Query
  /// Cross-site POST of an HTML form (OAuth 2.0 Form Post Response Mode).
  /// The browser-binding cookie then needs `SameSite=None; Secure`.
  FormPost
}

/// RFC 9207 `iss` authorization-response parameter policy. A present `iss`
/// must always equal the configured issuer.
pub type IssuerParameterPolicy {
  /// Require `iss` when the provider advertises
  /// `authorization_response_iss_parameter_supported`; accept its absence
  /// otherwise.
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
  /// field without `S256` is still refused. Warden cannot then know whether
  /// the provider enforces the challenge; for a confidential client, login
  /// still relies on client authentication and the mandatory nonce against
  /// code injection (RFC 9700 §2.1.1). Refused for public clients, which have
  /// no other protection for an intercepted code (decision D7).
  AssumeS256WhenUnadvertised
}

/// Trust anchors for provider TLS.
pub type Trust {
  /// The operating system's trust store (`public_key:cacerts_get/0`).
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

pub type Transport {
  Transport(
    trust: Trust,
    destinations: DestinationPolicy,
    /// When set, provider requests may only reach these host names.
    allowed_hosts: Option(List(String)),
    /// Deadline for one provider request, including resolution and connect.
    request_timeout_ms: Int,
    /// Maximum response body size.
    max_response_bytes: Int,
  )
}

pub type Settings {
  Settings(
    issuer: String,
    client_id: String,
    redirect_uri: String,
    authentication: ClientAuthentication,
    /// Scopes requested at login in addition to `openid`.
    scopes: List(String),
    signing_algorithms: List(SigningAlgorithm),
    response_mode: ResponseMode,
    issuer_parameter: IssuerParameterPolicy,
    pkce_advertisement: PkceAdvertisementPolicy,
    transport: Transport,
    /// Pending login lifetime.
    login_lifetime_seconds: Int,
    /// Maximum pending logins held by the built-in transaction store.
    max_pending_logins: Int,
    /// How long `warden.start` waits for discovery and keys.
    startup_timeout_ms: Int,
    /// Timeout for calls to Warden's own stores.
    store_timeout_ms: Int,
    /// Session lifetime in custody (see `with_session_lifetime`).
    session_absolute_seconds: Int,
    session_idle_seconds: Int,
  )
}

pub fn default_transport() -> Transport {
  Transport(
    trust: SystemTrust,
    destinations: PublicInternetOnly,
    allowed_hosts: None,
    request_timeout_ms: 10_000,
    max_response_bytes: 1_048_576,
  )
}

/// Settings with Warden's defaults: `openid` only, RS256/PS256/ES256/EdDSA,
/// query response mode, ten-minute pending logins, system trust and public
/// destinations only.
pub fn new(
  issuer issuer: String,
  client_id client_id: String,
  redirect_uri redirect_uri: String,
  authentication authentication: ClientAuthentication,
) -> Settings {
  Settings(
    issuer:,
    client_id:,
    redirect_uri:,
    authentication:,
    scopes: [],
    signing_algorithms: [Rs256, Ps256, Es256, EdDsa],
    response_mode: Query,
    issuer_parameter: RequireIssuerWhenAdvertised,
    pkce_advertisement: RequireAdvertisedS256,
    transport: default_transport(),
    login_lifetime_seconds: 600,
    max_pending_logins: 100_000,
    startup_timeout_ms: 15_000,
    store_timeout_ms: 5000,
    session_absolute_seconds: 43_200,
    session_idle_seconds: 3600,
  )
}

pub fn with_scopes(settings: Settings, scopes: List(String)) -> Settings {
  Settings(..settings, scopes:)
}

pub fn with_response_mode(settings: Settings, mode: ResponseMode) -> Settings {
  Settings(..settings, response_mode: mode)
}

pub fn with_signing_algorithms(
  settings: Settings,
  algorithms: List(SigningAlgorithm),
) -> Settings {
  Settings(..settings, signing_algorithms: algorithms)
}

pub fn with_transport(settings: Settings, transport: Transport) -> Settings {
  Settings(..settings, transport:)
}

pub fn with_trust(settings: Settings, trust: Trust) -> Settings {
  Settings(..settings, transport: Transport(..settings.transport, trust:))
}

pub fn with_destinations(
  settings: Settings,
  destinations: DestinationPolicy,
) -> Settings {
  Settings(
    ..settings,
    transport: Transport(..settings.transport, destinations:),
  )
}

pub fn with_login_lifetime(settings: Settings, seconds: Int) -> Settings {
  Settings(..settings, login_lifetime_seconds: seconds)
}

pub fn with_pkce_advertisement(
  settings: Settings,
  policy: PkceAdvertisementPolicy,
) -> Settings {
  Settings(..settings, pkce_advertisement: policy)
}

pub fn with_issuer_parameter(
  settings: Settings,
  policy: IssuerParameterPolicy,
) -> Settings {
  Settings(..settings, issuer_parameter: policy)
}

// ---------------------------------------------------------------------------
// Validation

pub type ConfigError {
  /// The issuer must be an absolute `https` URI without query or fragment.
  InvalidIssuer
  InvalidClientId
  /// The redirect URI must be absolute, without fragment, and `https` unless
  /// its host is a loopback address or `localhost`.
  InvalidRedirectUri
  /// A scope token contains a byte outside RFC 6749 §3.3 or is empty.
  InvalidScope(String)
  NoSigningAlgorithms
  /// The signing key cannot produce any assertion algorithm.
  SigningKeyUnusable
  InvalidTrustAnchors
  InvalidAllowedHost(String)
  InvalidLimit(String)
  /// `AssumeS256WhenUnadvertised` with `PublicClient`.
  UnadvertisedPkceRequiresConfidentialClient
  /// A client secret is empty.
  EmptyClientSecret
  /// A `client_secret_jwt` secret is shorter than 32 bytes, the minimum HMAC
  /// key for HS256 (RFC 7518 §3.2).
  ClientSecretTooShort
  /// Session lifetimes must be positive, with idle not above absolute.
  InvalidSessionLifetime
}

/// A validated configuration.
pub opaque type Config {
  Config(
    issuer: String,
    client_id: String,
    redirect_uri: String,
    authentication: ClientAuthentication,
    scopes: List(String),
    signing_algorithms: List(String),
    response_mode: ResponseMode,
    issuer_parameter: IssuerParameterPolicy,
    pkce_advertisement: PkceAdvertisementPolicy,
    trust: TrustAnchors,
    destinations: DestinationPolicy,
    allowed_hosts: Option(List(String)),
    request_timeout_ms: Int,
    max_response_bytes: Int,
    login_lifetime_seconds: Int,
    max_pending_logins: Int,
    startup_timeout_ms: Int,
    store_timeout_ms: Int,
    session_absolute_seconds: Int,
    session_idle_seconds: Int,
  )
}

/// Trust anchors after validation: the system store or DER certificates.
pub type TrustAnchors {
  SystemAnchors
  CertificateAnchors(List(BitArray))
}

/// Validate settings. Returns every problem found.
pub fn validate(settings: Settings) -> Result(Config, List(ConfigError)) {
  let trust = case settings.transport.trust {
    SystemTrust -> Ok(SystemAnchors)
    TrustAnchorsPem(pem) ->
      pem_certificates(pem)
      |> result.map(CertificateAnchors)
      |> result.replace_error(InvalidTrustAnchors)
  }
  let scopes = normalise_scopes(settings.scopes)
  let algorithms =
    settings.signing_algorithms
    |> list.map(algorithm_name)
    |> list.unique
  let checks = [
    check(valid_issuer(settings.issuer), InvalidIssuer),
    check(valid_client_id(settings.client_id), InvalidClientId),
    check(valid_redirect_uri(settings.redirect_uri), InvalidRedirectUri),
    check(algorithms != [], NoSigningAlgorithms),
    check(authentication_usable(settings.authentication), SigningKeyUnusable),
    limit(
      settings.transport.request_timeout_ms,
      1,
      300_000,
      "request_timeout_ms",
    ),
    limit(
      settings.transport.max_response_bytes,
      1024,
      67_108_864,
      "max_response_bytes",
    ),
    limit(settings.login_lifetime_seconds, 1, 86_400, "login_lifetime_seconds"),
    limit(settings.max_pending_logins, 1, 10_000_000, "max_pending_logins"),
    limit(settings.startup_timeout_ms, 1, 600_000, "startup_timeout_ms"),
    limit(settings.store_timeout_ms, 1, 600_000, "store_timeout_ms"),
    result.map(trust, fn(_) { Nil }),
    check(
      settings.pkce_advertisement == RequireAdvertisedS256
        || settings.authentication != PublicClient,
      UnadvertisedPkceRequiresConfidentialClient,
    ),
    check(
      settings.session_idle_seconds > 0
        && settings.session_idle_seconds <= settings.session_absolute_seconds
        && settings.session_absolute_seconds <= 31_536_000,
      InvalidSessionLifetime,
    ),
    check(client_secret_present(settings.authentication), EmptyClientSecret),
    check(jwt_secret_long_enough(settings.authentication), ClientSecretTooShort),
  ]
  let scope_errors =
    scopes
    |> list.filter(fn(scope) { !valid_scope(scope) })
    |> list.map(InvalidScope)
  let host_errors = case settings.transport.allowed_hosts {
    None -> []
    Some(hosts) ->
      hosts
      |> list.filter(fn(host) { !valid_host(host) })
      |> list.map(InvalidAllowedHost)
  }
  let errors =
    list.flatten([
      list.filter_map(checks, fn(c) {
        case c {
          Ok(_) -> Error(Nil)
          Error(e) -> Ok(e)
        }
      }),
      scope_errors,
      host_errors,
    ])
  case errors, trust {
    [], Ok(anchors) ->
      Ok(Config(
        issuer: settings.issuer,
        client_id: settings.client_id,
        redirect_uri: settings.redirect_uri,
        authentication: settings.authentication,
        scopes: ["openid", ..scopes],
        signing_algorithms: algorithms,
        response_mode: settings.response_mode,
        issuer_parameter: settings.issuer_parameter,
        pkce_advertisement: settings.pkce_advertisement,
        trust: anchors,
        destinations: settings.transport.destinations,
        allowed_hosts: option.map(settings.transport.allowed_hosts, list.map(
          _,
          string.lowercase,
        )),
        request_timeout_ms: settings.transport.request_timeout_ms,
        max_response_bytes: settings.transport.max_response_bytes,
        login_lifetime_seconds: settings.login_lifetime_seconds,
        max_pending_logins: settings.max_pending_logins,
        startup_timeout_ms: settings.startup_timeout_ms,
        store_timeout_ms: settings.store_timeout_ms,
        session_absolute_seconds: settings.session_absolute_seconds,
        session_idle_seconds: settings.session_idle_seconds,
      ))
    _, _ -> Error(errors)
  }
}

fn check(condition: Bool, error: ConfigError) -> Result(Nil, ConfigError) {
  case condition {
    True -> Ok(Nil)
    False -> Error(error)
  }
}

fn limit(
  value: Int,
  low: Int,
  high: Int,
  name: String,
) -> Result(Nil, ConfigError) {
  check(value >= low && value <= high, InvalidLimit(name))
}

fn normalise_scopes(scopes: List(String)) -> List(String) {
  scopes
  |> list.filter(fn(s) { s != "openid" })
  |> list.unique
}

/// RFC 6749 §3.3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E ). Case is
/// preserved.
pub fn valid_scope(scope: String) -> Bool {
  let bytes = bit_array.from_string(scope)
  bit_array.byte_size(bytes) > 0 && scope_bytes_valid(bytes)
}

fn scope_bytes_valid(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> True
    <<byte, rest:bytes>> ->
      {
        byte == 0x21
        || { byte >= 0x23 && byte <= 0x5B }
        || { byte >= 0x5D && byte <= 0x7E }
      }
      && scope_bytes_valid(rest)
    _ -> False
  }
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

fn valid_client_id(client_id: String) -> Bool {
  client_id != "" && string.length(client_id) <= 512
}

/// Redirect URIs must be absolute, fragment-free and `https`, except `http`
/// for loopback hosts (`127.0.0.1`, `[::1]`, `localhost`).
pub fn valid_redirect_uri(redirect: String) -> Bool {
  case uri.parse(redirect) {
    Ok(uri.Uri(
      scheme: Some(scheme),
      userinfo: None,
      host: Some(host),
      fragment: None,
      ..,
    )) ->
      host != ""
      && !string.contains(redirect, "#")
      && case scheme {
        "https" -> True
        "http" -> host == "127.0.0.1" || host == "::1" || host == "localhost"
        _ -> False
      }
    _ -> False
  }
}

fn valid_host(host: String) -> Bool {
  host != "" && !string.contains(host, "/") && !string.contains(host, ":")
}

fn client_secret_present(authentication: ClientAuthentication) -> Bool {
  case authentication {
    ClientSecretBasic(secret)
    | ClientSecretPost(secret)
    | ClientSecretJwt(secret) -> secret.reveal() != ""
    _ -> True
  }
}

/// RFC 7518 §3.2: an HMAC key at least as long as the hash output.
fn hmac_key_bytes(algorithm: String) -> Int {
  case algorithm {
    "HS384" -> 48
    "HS512" -> 64
    _ -> 32
  }
}

fn jwt_secret_long_enough(authentication: ClientAuthentication) -> Bool {
  case authentication {
    ClientSecretJwt(secret) ->
      secret.reveal() == ""
      || string.byte_size(secret.reveal()) >= hmac_key_bytes("HS256")
    _ -> True
  }
}

fn authentication_usable(authentication: ClientAuthentication) -> Bool {
  case authentication {
    PrivateKeyJwt(key) -> key.algorithms != []
    _ -> True
  }
}

pub fn algorithm_name(algorithm: SigningAlgorithm) -> String {
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

// ---------------------------------------------------------------------------
// Accessors for Warden's own modules. These expose validated configuration,
// never secret values; secrets cross only to the trusted backend boundary.

@internal
pub fn issuer(config: Config) -> String {
  config.issuer
}

@internal
pub fn client_id(config: Config) -> String {
  config.client_id
}

@internal
pub fn redirect_uri(config: Config) -> String {
  config.redirect_uri
}

@internal
pub fn scopes(config: Config) -> List(String) {
  config.scopes
}

@internal
pub fn signing_algorithms(config: Config) -> List(String) {
  config.signing_algorithms
}

@internal
pub fn response_mode(config: Config) -> ResponseMode {
  config.response_mode
}

@internal
pub fn issuer_parameter(config: Config) -> IssuerParameterPolicy {
  config.issuer_parameter
}

pub fn pkce_advertisement(config: Config) -> PkceAdvertisementPolicy {
  config.pkce_advertisement
}

@internal
pub fn login_lifetime_seconds(config: Config) -> Int {
  config.login_lifetime_seconds
}

@internal
pub fn max_pending_logins(config: Config) -> Int {
  config.max_pending_logins
}

@internal
pub fn startup_timeout_ms(config: Config) -> Int {
  config.startup_timeout_ms
}

@internal
pub fn store_timeout_ms(config: Config) -> Int {
  config.store_timeout_ms
}

@internal
pub fn request_timeout_ms(config: Config) -> Int {
  config.request_timeout_ms
}

@internal
pub fn max_response_bytes(config: Config) -> Int {
  config.max_response_bytes
}

@internal
pub fn trust_anchors(config: Config) -> TrustAnchors {
  config.trust
}

@internal
pub fn destinations(config: Config) -> DestinationPolicy {
  config.destinations
}

@internal
pub fn allowed_hosts(config: Config) -> Option(List(String)) {
  config.allowed_hosts
}

/// Authentication method name as used in provider metadata.
@internal
pub fn authentication_method(config: Config) -> String {
  case config.authentication {
    PublicClient -> "none"
    ClientSecretBasic(_) -> "client_secret_basic"
    ClientSecretPost(_) -> "client_secret_post"
    ClientSecretJwt(_) -> "client_secret_jwt"
    PrivateKeyJwt(_) -> "private_key_jwt"
  }
}

/// The credential for the trusted backend boundary: the secret or private
/// JWK text, or nothing for a public client.
@internal
pub fn trusted_credential(config: Config) -> Option(String) {
  case config.authentication {
    PublicClient -> None
    ClientSecretBasic(s) | ClientSecretPost(s) | ClientSecretJwt(s) ->
      Some(s.reveal())
    PrivateKeyJwt(k) -> Some(k.reveal())
  }
}

/// Assertion algorithms usable with the configured client authentication.
@internal
pub fn assertion_algorithms(config: Config) -> List(String) {
  case config.authentication {
    // Only the algorithms the secret is long enough for.
    ClientSecretJwt(secret) ->
      list.filter(["HS256", "HS384", "HS512"], fn(algorithm) {
        string.byte_size(secret.reveal()) >= hmac_key_bytes(algorithm)
      })
    PrivateKeyJwt(key) -> key.algorithms
    _ -> []
  }
}

/// Test-only view: configured signing key id, used in assertions checks.
@internal
pub fn signing_key_id(config: Config) -> Option(String) {
  case config.authentication {
    PrivateKeyJwt(key) -> key.key_id
    _ -> None
  }
}

/// The transport policy derived from validated configuration.
@internal
pub fn transport_policy(config: Config) -> transport.Policy {
  let #(allow_loopback, allow_private) = case config.destinations {
    PublicInternetOnly -> #(False, False)
    AllowLoopbackForTesting -> #(True, False)
    AllowPrivateNetwork -> #(False, True)
  }
  transport.Policy(
    ..transport.policy(case config.trust {
      SystemAnchors -> transport.SystemTrust
      CertificateAnchors(certs) -> transport.Anchors(certs)
    }),
    allow_loopback:,
    allow_private:,
    allowed_hosts: config.allowed_hosts,
    timeout_ms: config.request_timeout_ms,
    max_body: config.max_response_bytes,
  )
}

/// How long a session lasts in custody: `absolute` seconds after login at
/// most, and `idle` seconds without use (restore, access token, userinfo,
/// refresh). Expired sessions are evicted with their tokens. Defaults: 12
/// hours absolute, 1 hour idle.
pub fn with_session_lifetime(
  settings: Settings,
  absolute absolute: Int,
  idle idle: Int,
) -> Settings {
  Settings(
    ..settings,
    session_absolute_seconds: absolute,
    session_idle_seconds: idle,
  )
}

/// `#(absolute_seconds, idle_seconds)`.
pub fn session_lifetime(config: Config) -> #(Int, Int) {
  #(config.session_absolute_seconds, config.session_idle_seconds)
}
