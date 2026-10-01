//// Gleam wrappers over the Erlang test support.

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
