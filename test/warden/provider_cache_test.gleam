//// The provider cache keeps serving its last good snapshot while a key
//// refresh or reload is slow (internal security review, finding J2).

import gleam/erlang/process
import warden/internal/native/provider
import warden/internal/transport
import warden/testing

@external(erlang, "warden_fetch_ownership_test", "slow_key_refresh_does_not_block_cached_snapshots")
pub fn slow_key_refresh_does_not_block_cached_snapshots_test() -> Nil

/// Test fixture construction stays typed; lifecycle tests observe the actor
/// through its existing handle rather than unpacking its private state.
fn lifecycle_policy(fixture: testing.Provider) -> transport.Policy {
  transport.Policy(
    ..transport.policy(transport.Anchors([testing.trust_anchor_der(fixture)])),
    allow_loopback: True,
    timeout_ms: 5000,
  )
}

pub fn start_for_lifecycle(
  fixture: testing.Provider,
) -> #(process.Pid, provider.Provider) {
  let name = process.new_name("provider_cache_lifecycle")
  let assert Ok(started) =
    provider.start(
      name,
      testing.issuer(fixture),
      lifecycle_policy(fixture),
      fn(_) { True },
    )
  #(started.pid, provider.Provider(started.data, 5000))
}
