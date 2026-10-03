//// The configuration record behind `warden/config.Config`. Only
//// `warden/config` builds it; `warden.new` validates it, and Warden's own
//// modules read it. Secret material is held behind closures (`Redacted`), so
//// printing a configuration shows no credential.

import gleam/list
import gleam/option.{type Option}
import gleam/string
import warden/internal/redacted.{type Redacted}
import warden/store.{type Store}

/// What the client is configured to do.
pub type Mode {
  /// Login (authorization code flow) plus every other operation.
  RelyingParty
  /// Client credentials, introspection and token validation; no login.
  ServiceClient
  /// Local access-token validation only; no client identity at all.
  ResourceServer
}

/// Client authentication, with secrets behind closures.
pub type Authentication {
  /// `none`: a public client sends only its `client_id`.
  NoClientAuthentication
  /// `client_secret_basic`, `client_secret_post` or `client_secret_jwt`.
  SharedSecret(method: String, secret: Redacted(String))
  /// `private_key_jwt`.
  PrivateKey(
    jwk: Redacted(String),
    key_id: Option(String),
    algorithms: List(String),
  )
}

pub type ResponseMode {
  Query
  FormPost
}

pub type Trust {
  SystemTrust
  Anchors(List(BitArray))
  /// The PEM text given to `with_trust` did not decode; `validate` reports
  /// it.
  UnreadableAnchors
}

pub type Destinations {
  PublicOnly
  AllowLoopback
  AllowPrivate
}

pub type Settings {
  Settings(
    mode: Mode,
    issuer: String,
    client_id: String,
    /// Empty unless `mode` is `RelyingParty`.
    redirect_uri: String,
    /// Further redirect URIs a login may choose, matched exactly.
    allowed_redirect_uris: List(String),
    authentication: Authentication,
    /// `service_client` was given a public client.
    service_without_credentials: Bool,
    /// Extra login scopes, without `openid`.
    scopes: List(String),
    signing_algorithms: List(String),
    response_mode: ResponseMode,
    always_require_issuer: Bool,
    assume_s256: Bool,
    trust: Trust,
    destinations: Destinations,
    allowed_hosts: Option(List(String)),
    request_timeout_ms: Int,
    max_response_bytes: Int,
    startup_timeout_ms: Int,
    store_timeout_ms: Int,
    login_timeout_ms: Int,
    login_lifetime_seconds: Int,
    max_pending_logins: Int,
    session_absolute_seconds: Int,
    session_idle_seconds: Int,
    clock_tolerance_seconds: Int,
    refresh_margin_seconds: Int,
    refresh_wait_ms: Int,
    custody_store: Option(Store),
    transaction_store: Option(Store),
    sealing_key: Option(Redacted(BitArray)),
    previous_sealing_keys: List(Redacted(BitArray)),
    /// Unix time in seconds. A test seam: production uses the system clock.
    clock: fn() -> Int,
  )
}

/// `none`, `client_secret_basic`, ... as provider metadata names them.
pub fn authentication_method(settings: Settings) -> String {
  case settings.authentication {
    NoClientAuthentication -> "none"
    SharedSecret(method:, ..) -> method
    PrivateKey(..) -> "private_key_jwt"
  }
}

/// True when the client authenticates itself to the provider.
pub fn confidential(settings: Settings) -> Bool {
  case settings.authentication {
    NoClientAuthentication -> False
    _ -> True
  }
}

/// The secret or private JWK text for the backend, or nothing.
pub fn credential(settings: Settings) -> Option(String) {
  case settings.authentication {
    NoClientAuthentication -> option.None
    SharedSecret(secret:, ..) -> option.Some(redacted.reveal(secret))
    PrivateKey(jwk:, ..) -> option.Some(redacted.reveal(jwk))
  }
}

/// RFC 7518 §3.2: an HMAC key at least as long as the hash output.
pub fn hmac_key_bytes(algorithm: String) -> Int {
  case algorithm {
    "HS384" -> 48
    "HS512" -> 64
    _ -> 32
  }
}

/// Client-assertion algorithms usable with the configured authentication.
pub fn assertion_algorithms(settings: Settings) -> List(String) {
  case settings.authentication {
    SharedSecret(method: "client_secret_jwt", secret:) -> {
      let size = string.byte_size(redacted.reveal(secret))
      list.filter(["HS256", "HS384", "HS512"], fn(algorithm) {
        size >= hmac_key_bytes(algorithm)
      })
    }
    PrivateKey(algorithms:, ..) -> algorithms
    _ -> []
  }
}
