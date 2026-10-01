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

/// A reservation whose holder dies is orphaned: new reservations are
/// refused as quarantined, and the dispatch's own publication is still
/// accepted (finding F7).
pub fn an_orphaned_reservation_accepts_only_its_publication_test() {
  let store = start(100)
  let assert Ok(custody.Installed(receipt)) =
    custody.install(store, command("a", 1))
  let reserved = process.new_subject()
  let holder =
    process.spawn_unlinked(fn() {
      let assert Ok(custody.Reserved(dispatch)) =
        custody.reserve_refresh(store, receipt.reference, "provider", 1, "r1")
      process.send(reserved, dispatch)
      process.sleep_forever()
    })
  let assert Ok(dispatch) = process.receive(reserved, 1000)
  process.kill(holder)
  process.sleep(50)
  assert custody.reserve_refresh(store, receipt.reference, "provider", 1, "r2")
    == Ok(custody.ReservationQuarantined)
  let assert Ok(custody.Published(published)) =
    custody.publish_refresh(
      store,
      custody.Publish(
        reference: receipt.reference,
        dispatch_id: dispatch.dispatch_id,
        command_id: "p1",
        update: custody.Update(
          access_token: "at-2",
          token_type: "Bearer",
          expires_at: None,
          refresh_token: custody.ReplaceWith("rt-2"),
          id_token: custody.Retain,
          scopes: custody.Retain,
        ),
      ),
    )
  assert published.revision == 2
}
