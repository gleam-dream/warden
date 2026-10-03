//// The provider cache keeps serving its last good snapshot while a key
//// refresh or reload is slow (internal security review, finding J2).

import gleam/erlang/process
import gleam/option.{Some}
import warden/internal/native/provider
import warden/internal/transport
import warden_test_support as support

fn policy() -> transport.Policy {
  transport.Policy(
    ..transport.policy(transport.Anchors([support.ca_der()])),
    allow_loopback: True,
    timeout_ms: 5000,
  )
}

pub fn slow_key_refresh_does_not_block_cached_snapshots_test() {
  let issuer_provider = support.provider_start(support.Standard)
  let issuer = support.provider_issuer(issuer_provider)
  let assert Ok(discovered) =
    provider.discover(issuer, policy(), transport.monotonic_ms() + 5000)
  // Keys now come from a server that answers after 3 s.
  let slow = support.server_start("localhost", support.Slow)
  let seed =
    provider.Discovered(..discovered, jwks_uri: support.server_url(slow, "/k"))
  let name = process.new_name("provider_cache_test")
  let assert Ok(_) =
    provider.start(name, issuer, policy(), Some(seed), fn(_) { True })
  let subject = process.named_subject(name)
  process.spawn(fn() {
    provider.refresh_keys(provider.Provider(subject, 5000), Some("new-kid"))
  })
  process.sleep(100)
  let started = transport.monotonic_ms()
  let assert Ok(_) = provider.snapshot_of(provider.Provider(subject, 1000))
  assert transport.monotonic_ms() - started < 200
  support.server_stop(slow)
  support.provider_stop(issuer_provider)
}
