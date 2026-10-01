//// Gleam wrappers over the Erlang test support.

import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import warden/config
import warden/internal/oidcc_transport
import warden/internal/secure
import warden/internal/transport

pub type BrowserResult {
  Query(String)
  FormPost(String)
}

@external(erlang, "warden_test_support_ffi", "ca_pem")
pub fn ca_pem() -> String

@external(erlang, "warden_test_support_ffi", "pki_file")
pub fn pki_file(name: String) -> String

@external(erlang, "warden_test_support_ffi", "keycloak_login")
pub fn keycloak_login(
  url: String,
  user: String,
  password: String,
) -> Result(BrowserResult, Nil)

@external(erlang, "warden_test_support_ffi", "authorize")
pub fn authorize(
  url: String,
  provider_prefix: String,
) -> Result(BrowserResult, Nil)

@external(erlang, "warden_test_support_ffi", "visit")
pub fn visit(url: String) -> Result(BrowserResult, Nil)

@external(erlang, "warden_test_support_ffi", "count_reset")
pub fn count_reset() -> Nil

/// Transport requests observed for URL paths ending with `suffix`.
@external(erlang, "warden_test_support_ffi", "count")
pub fn count(suffix: String) -> Int

/// Run functions concurrently after a common release; results in order.
@external(erlang, "warden_test_support_ffi", "spawn_collect")
pub fn spawn_collect(functions: List(fn() -> a), timeout_ms: Int) -> List(a)

@external(erlang, "timer", "sleep")
pub fn sleep(ms: Int) -> a

pub type Clock

@external(erlang, "warden_test_support_ffi", "clock_new")
pub fn clock_new(start: Int) -> Clock

@external(erlang, "warden_test_support_ffi", "clock_set")
pub fn clock_set(clock: Clock, value: Int) -> Nil

@external(erlang, "warden_test_support_ffi", "clock_read")
pub fn clock_read(clock: Clock) -> Int

pub type Provider

pub type ProviderVariant {
  Standard
  NoS256
  RequiresPar
  NoEndSession
  WrongIssuer
  NoIssParameter
  NoFormPost
  Hs256Only
}

@external(erlang, "warden_test_support_ffi", "provider_start")
pub fn provider_start(variant: ProviderVariant) -> Provider

@external(erlang, "warden_test_provider", "stop")
pub fn provider_stop(provider: Provider) -> Nil

@external(erlang, "warden_test_provider", "issuer")
pub fn provider_issuer(provider: Provider) -> String

@external(erlang, "warden_test_provider", "issue_code")
pub fn issue_code(provider: Provider, code: String, nonce: String) -> Nil

@external(erlang, "warden_test_provider", "token_requests")
pub fn token_requests(provider: Provider) -> Int

@external(erlang, "warden_test_provider", "set_claims")
pub fn set_claims(provider: Provider, claims: Dict(String, String)) -> Nil

pub type ScriptKey {
  Code(String)
  Refresh(String)
  Userinfo
}

pub type Behaviour {
  Delay(Int)
  Status(Int, String)
  Close
  MalformedJson
  IdToken(String)
  OmitIdToken
  DropRefreshToken
  Sub(String)
}

@external(erlang, "warden_test_provider", "script")
pub fn script(provider: Provider, key: ScriptKey, behaviour: Behaviour) -> Nil

@external(erlang, "warden_test_provider", "refresh_tokens")
pub fn refresh_tokens(provider: Provider) -> List(String)

@external(erlang, "warden_test_support_ffi", "keycloak_logout")
pub fn keycloak_logout(url: String) -> Result(BrowserResult, Nil)

pub type NodeAction {
  NodeIdToken(String)
  NodeOmitIdToken
  NodeDropRefreshToken
  NodeDelayMs(Int)
  NodeStatus(Int)
}

@external(erlang, "warden_test_support_ffi", "node_reset")
pub fn node_reset() -> Nil

@external(erlang, "warden_test_support_ffi", "node_next")
pub fn node_next(grant: String, actions: List(NodeAction)) -> Nil

/// Token-endpoint requests seen by the node provider:
/// `#(grant_type, client_id, assertion)` where assertion is `none`,
/// `verified:<alg>` (checked by panva/jose) or `rejected`.
@external(erlang, "warden_test_support_ffi", "node_log")
pub fn node_log() -> List(#(String, String, String))

@external(erlang, "warden_test_support_ffi", "print")
pub fn print(line: String) -> Nil

/// Interactive provider login: follow redirects and submit HTML forms with
/// the given fields until the provider redirects to the client.
@external(erlang, "warden_test_support_ffi", "form_login")
pub fn form_login(
  url: String,
  provider_prefix: String,
  fields: List(#(String, String)),
) -> Result(BrowserResult, Nil)

@external(erlang, "warden_test_provider", "rotate_key")
pub fn rotate_key(provider: Provider) -> Nil

pub type WorkerName

@external(erlang, "warden_test_support_ffi", "worker_kill")
pub fn worker_kill(name: a) -> Nil

@external(erlang, "warden_test_support_ffi", "worker_alive")
pub fn worker_alive(name: a) -> Bool

@external(erlang, "warden_test_support_ffi", "atom_count")
pub fn atom_count() -> Int

@external(erlang, "warden_test_support_ffi", "process_count")
pub fn process_count() -> Int

pub type TestServer

pub type Canned {
  OkJson
  Redirect
  DeclaredOversize
  EndlessChunked
  CloseDelimitedOversize
  ChunkedOk
  Interim
  Slow
  ManyHeaders
  BigHeaderLine
  Gzip
  ErrorBody
  HtmlError
  BadJson
  Truncated
  BadStatus
}

@external(erlang, "warden_test_support_ffi", "server_start")
pub fn server_start(cert: String, kind: Canned) -> TestServer

@external(erlang, "warden_test_support_ffi", "server_url")
pub fn server_url(server: TestServer, path: String) -> String

/// Requests the server has received so far.
@external(erlang, "warden_test_support_ffi", "server_requests")
pub fn server_requests(server: TestServer) -> Int

@external(erlang, "warden_test_support_ffi", "server_stop")
pub fn server_stop(server: TestServer) -> Nil

@external(erlang, "warden_test_support_ffi", "ca_der")
pub fn ca_der() -> BitArray

/// The oidcc adapter term trusting the test CA and allowing loopback, for
/// Erlang probes that call raw oidcc.
pub fn test_adapter(timeout_ms: Int) -> Dynamic {
  oidcc_transport.adapter(
    transport.Policy(
      ..transport.policy(transport.Anchors([ca_der()])),
      allow_loopback: True,
      timeout_ms:,
    ),
  )
}

/// As `test_adapter` but with the default destination policy.
pub fn strict_adapter() -> Dynamic {
  oidcc_transport.adapter(transport.policy(transport.Anchors([ca_der()])))
}

@external(erlang, "warden_test_support_ffi", "backend_env")
fn backend_env() -> String

pub fn backend_name() -> String {
  backend_env()
}

/// Apply the backend selected by `WARDEN_BACKEND` (native by default).
pub fn with_test_backend(settings: config.Settings) -> config.Settings {
  case backend_env() {
    "oidcc" -> config.with_backend(settings, config.OidccBackend)
    _ -> config.with_backend(settings, config.NativeBackend)
  }
}

pub fn now_seconds() -> Int {
  secure.now_seconds()
}
