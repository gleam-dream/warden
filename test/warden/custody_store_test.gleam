//// Custody installation replays never resurrect an ended session or install
//// a second session after the receipt left the bounded history (internal
//// security review, finding F5).

import gleam/erlang/process
import gleam/int
import gleam/option.{None, Some}
import warden/internal/custody_store as custody
import warden/internal/secure

fn start(history_limit: Int) -> custody.Store(String) {
  let name = process.new_name("custody_store_test")
  let assert Ok(_) =
    custody.start(
      new_reference: fn() { secure.random_token(32) },
      history_limit:,
      name:,
    )
  custody.Store(process.named_subject(name), 5000)
}

fn command(id: String, issued_at: Int) -> custody.Install(String) {
  custody.Install(
    command_id: id,
    issued_at:,
    provider: "provider",
    identity: "alice",
    evidence: custody.Evidence(nonce: "n", auth_time: None),
    tokens: custody.Tokens(
      access_token: "at-" <> id,
      token_type: "Bearer",
      expires_at: None,
      refresh_token: Some("rt-" <> id),
      id_token: None,
      scopes: [],
    ),
  )
}

pub fn replay_after_removal_reports_the_session_ended_test() {
  let store = start(100)
  let assert Ok(custody.Installed(receipt)) =
    custody.install(store, command("a", 1))
  // Replays before removal return the same receipt (idempotent).
  assert custody.install(store, command("a", 1))
    == Ok(custody.Installed(receipt))
  let assert Ok(Nil) = custody.remove(store, receipt.reference)
  assert custody.install(store, command("a", 1)) == Ok(custody.InstallEnded)
}

pub fn replay_after_eviction_is_refused_not_reinstalled_test() {
  let store = start(4)
  let assert Ok(custody.Installed(first)) =
    custody.install(store, command("c1", 1))
  int.range(from: 2, to: 11, with: Nil, run: fn(_, i) {
    let assert Ok(custody.Installed(_)) =
      custody.install(store, command("c" <> int.to_string(i), i))
    Nil
  })
  // c1's receipt was evicted: refuse instead of installing a second session
  // that shares its refresh token.
  assert custody.install(store, command("c1", 1)) == Ok(custody.InstallExpired)
  // The original session is untouched.
  let assert Ok(Ok(_)) = custody.get(store, first.reference)
}
