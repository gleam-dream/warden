//// Gleam wrappers over the Erlang test support.

import gleam/dict.{type Dict}

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
