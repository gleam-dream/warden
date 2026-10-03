//// Custody over the record store: idempotent installation, tombstones,
//// leases that quarantine, publication of an orphaned dispatch, lifetimes,
//// sealing and tampering (findings F2, F5, F7; decisions D19 to D21).

import gleam/bit_array
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleam/time/timestamp
import warden/internal/custody
import warden/internal/port
import warden/internal/redacted
import warden/internal/sealed
import warden/internal/secure
import warden/store
import warden/testing
import warden_test_support as support

type Rig {
  Rig(custody: custody.Custody, store: store.Store, clock: support.Clock)
}

fn rig(absolute: Int, idle: Int) -> Rig {
  let clock = support.clock_new(10_000)
  let store = testing.memory_store()
  let custody =
    custody.Custody(
      port: port.Port(store:, timeout_ms: 5000),
      keys: sealed.keys(redacted.new(<<7:256>>), []),
      clock: fn() { support.clock_read(clock) },
      absolute:,
      idle:,
      retention: 600,
      epoch: None,
    )
  Rig(custody:, store:, clock:)
}

fn command(rig: Rig, id: String) -> custody.Install {
  custody.Install(
    reference: "ref-" <> id,
    command_id: id,
    issued_at: support.clock_read(rig.clock),
    provider: "provider",
    identity: custody.Identity(
      issuer: "https://idp",
      subject: "alice",
      claims: "{\"sub\":\"alice\"}",
    ),
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

fn update() -> custody.Update {
  custody.Update(
    access_token: "at-2",
    token_type: "Bearer",
    expires_at: None,
    refresh_token: custody.ReplaceWith("rt-2"),
    id_token: custody.Retain,
    scopes: custody.Retain,
  )
}

pub fn replay_after_removal_reports_the_session_ended_test() {
  let rig = rig(100_000, 100_000)
  let install = command(rig, "a")
  assert custody.install(rig.custody, install) == custody.Installed(1)
  // Replays before removal return the same receipt (idempotent).
  assert custody.install(rig.custody, install) == custody.Installed(1)
  assert custody.remove(rig.custody, "ref-a", "other-provider")
    == custody.RemovalForeign
  let assert custody.Removed(snapshot) =
    custody.remove(rig.custody, "ref-a", "provider")
  assert snapshot.entry.tokens.access_token == "at-a"
  assert custody.remove(rig.custody, "ref-a", "provider")
    == custody.RemovalMissing
  // The tombstone outlives the session: a replay cannot resurrect it.
  assert custody.install(rig.custody, install) == custody.InstallEnded
}

pub fn an_old_command_is_refused_not_reinstalled_test() {
  let rig = rig(100_000, 100_000)
  let install = command(rig, "old")
  support.clock_set(rig.clock, 10_000 + 601)
  assert custody.install(rig.custody, install) == custody.InstallExpired
  assert custody.get(rig.custody, "ref-old") == Error(custody.Missing)
}

/// A reservation whose lease runs out is orphaned: new reservations are
/// refused as quarantined, never released, and the dispatch's own
/// publication is still accepted (finding F7).
pub fn an_expired_lease_quarantines_but_accepts_its_publication_test() {
  let rig = rig(100_000, 100_000)
  let assert custody.Installed(1) =
    custody.install(rig.custody, command(rig, "a"))
  let assert custody.Reserved(dispatch) =
    custody.reserve(rig.custody, "ref-a", "provider", 1, "r1", 10)
  assert custody.reserve(rig.custody, "ref-a", "provider", 1, "r2", 10)
    == custody.Busy
  support.clock_set(rig.clock, 10_000 + 10)
  assert custody.reserve(rig.custody, "ref-a", "provider", 1, "r2", 10)
    == custody.ReservationQuarantined("refresher_lost")
  // A late settlement as not sent does not release an orphaned generation.
  assert !custody.settle(
    rig.custody,
    "ref-a",
    dispatch.dispatch_id,
    custody.SettleNotSent,
  )
  let assert custody.Published(published) =
    custody.publish(
      rig.custody,
      custody.Publish(
        reference: "ref-a",
        provider: "provider",
        dispatch_id: dispatch.dispatch_id,
        command_id: "p1",
        update: update(),
      ),
    )
  assert published.entry.revision == 2
  assert published.entry.tokens.refresh_token == Some("rt-2")
  // Republishing the same command returns the receipt again.
  let assert custody.Published(again) =
    custody.publish(
      rig.custody,
      custody.Publish(
        reference: "ref-a",
        provider: "provider",
        dispatch_id: dispatch.dispatch_id,
        command_id: "p1",
        update: update(),
      ),
    )
  assert again.entry.revision == 2
}

pub fn settlement_releases_revokes_or_quarantines_test() {
  let rig = rig(100_000, 100_000)
  let assert custody.Installed(1) =
    custody.install(rig.custody, command(rig, "a"))
  let reserve = fn(id) {
    custody.reserve(rig.custody, "ref-a", "provider", 1, id, 30)
  }
  let assert custody.Reserved(first) = reserve("r1")
  assert custody.settle(
    rig.custody,
    "ref-a",
    first.dispatch_id,
    custody.SettleNotSent,
  )
  let assert custody.Reserved(second) = reserve("r2")
  assert custody.settle(
    rig.custody,
    "ref-a",
    second.dispatch_id,
    custody.SettleQuarantine("provider_outcome_unknown"),
  )
  assert reserve("r3")
    == custody.ReservationQuarantined("provider_outcome_unknown")
  let assert custody.Installed(1) =
    custody.install(rig.custody, command(rig, "b"))
  let assert custody.Reserved(third) =
    custody.reserve(rig.custody, "ref-b", "provider", 1, "r4", 30)
  assert custody.settle(
    rig.custody,
    "ref-b",
    third.dispatch_id,
    custody.SettleRejected,
  )
  assert custody.reserve(rig.custody, "ref-b", "provider", 1, "r5", 30)
    == custody.ReservationRevoked
}

/// Sessions end after the idle lifetime without use and after the absolute
/// lifetime regardless of use (review finding F2).
pub fn sessions_expire_when_idle_test() {
  let rig = rig(1000, 60)
  let assert custody.Installed(1) =
    custody.install(rig.custody, command(rig, "a"))
  support.clock_set(rig.clock, 10_050)
  let assert Ok(_) = custody.get(rig.custody, "ref-a")
  // Each use restarts the idle period.
  support.clock_set(rig.clock, 10_100)
  let assert Ok(_) = custody.get(rig.custody, "ref-a")
  support.clock_set(rig.clock, 10_161)
  assert custody.get(rig.custody, "ref-a") == Error(custody.Missing)
}

pub fn sessions_expire_at_the_absolute_lifetime_test() {
  let rig = rig(100, 60)
  let assert custody.Installed(1) =
    custody.install(rig.custody, command(rig, "a"))
  support.clock_set(rig.clock, 10_050)
  let assert Ok(_) = custody.get(rig.custody, "ref-a")
  support.clock_set(rig.clock, 10_099)
  let assert Ok(_) = custody.get(rig.custody, "ref-a")
  support.clock_set(rig.clock, 10_100)
  assert custody.get(rig.custody, "ref-a") == Error(custody.Missing)
}

/// Abandoned sessions leave the store with their tokens once their record
/// expires, even if never used again.
pub fn expired_sessions_leave_the_store_test() {
  let rig = rig(1000, 60)
  let assert custody.Installed(1) =
    custody.install(rig.custody, command(rig, "a"))
  // The record outlives the session by the retention horizon (600 s), so a
  // late recovery still finds it ended.
  let assert Ok(1) =
    store.delete_expired(rig.store, timestamp.from_unix_seconds(10_000 + 601))
  assert store.get(rig.store, record_key("ref-a")) == Ok(None)
}

fn record_key(reference: String) -> String {
  "session:" <> secure.sha256_hex(reference)
}

/// The store sees digests and sealed bytes only: no reference, token,
/// subject or claim.
pub fn records_are_sealed_and_keyed_by_digest_test() {
  let rig = rig(100_000, 100_000)
  let assert custody.Installed(1) =
    custody.install(rig.custody, command(rig, "a"))
  assert store.get(rig.store, "ref-a") == Ok(None)
  let assert Ok(Some(record)) = store.get(rig.store, record_key("ref-a"))
  let printed = string.inspect(record) <> bit_array.base16_encode(record.sealed)
  assert !string.contains(printed, "ref-a")
  let raw = bit_array_text(record.sealed)
  assert !string.contains(raw, "at-a")
  assert !string.contains(raw, "rt-a")
  assert !string.contains(raw, "alice")
}

fn bit_array_text(bytes: BitArray) -> String {
  case bit_array.to_string(bytes) {
    Ok(text) -> text
    Error(Nil) -> string.inspect(bytes)
  }
}

/// A database writer cannot forge, move or roll a record forward: a
/// changed byte, another key's record or a renumbered version does not
/// open.
pub fn tampered_records_do_not_open_test() {
  let rig = rig(100_000, 100_000)
  let assert custody.Installed(1) =
    custody.install(rig.custody, command(rig, "a"))
  let assert custody.Installed(1) =
    custody.install(rig.custody, command(rig, "b"))
  let key_a = record_key("ref-a")
  let key_b = record_key("ref-b")
  let assert Ok(Some(a)) = store.get(rig.store, key_a)
  let assert Ok(Some(b)) = store.get(rig.store, key_b)
  // b's sealed bytes under a's key.
  let assert Ok(True) =
    store.put(rig.store, store.Record(..b, key: key_a, version: 2), Some(1))
  assert custody.get(rig.custody, "ref-a") == Error(custody.Unreadable)
  // a's own bytes with another version number.
  let assert Ok(True) =
    store.put(rig.store, store.Record(..a, version: 3), Some(2))
  assert custody.get(rig.custody, "ref-a") == Error(custody.Unreadable)
  // A flipped byte.
  let size = bit_array.byte_size(b.sealed)
  let assert Ok(head) = bit_array.slice(b.sealed, 0, size - 1)
  let assert Ok(True) =
    store.put(
      rig.store,
      store.Record(..b, sealed: <<head:bits, 0>>, version: 2),
      Some(1),
    )
  assert custody.get(rig.custody, "ref-b") == Error(custody.Unreadable)
}

/// Records sealed before a key rotation open with the retired key; new
/// records use the new one. Without the retired key they do not open.
pub fn sealing_keys_rotate_test() {
  let old = rig(100_000, 100_000)
  let assert custody.Installed(1) =
    custody.install(old.custody, command(old, "a"))
  let rotated =
    custody.Custody(
      ..old.custody,
      keys: sealed.keys(redacted.new(<<8:256>>), [redacted.new(<<7:256>>)]),
    )
  let assert Ok(_) = custody.get(rotated, "ref-a")
  let forgotten =
    custody.Custody(
      ..old.custody,
      keys: sealed.keys(redacted.new(<<8:256>>), []),
    )
  assert custody.get(forgotten, "ref-a") == Error(custody.Unreadable)
}

/// Concurrent reservations of one generation: exactly one dispatch.
pub fn concurrent_reservations_admit_one_dispatch_test() {
  let rig = rig(100_000, 100_000)
  let assert custody.Installed(1) =
    custody.install(rig.custody, command(rig, "a"))
  let attempt = fn() {
    case custody.reserve(rig.custody, "ref-a", "provider", 1, "r", 30) {
      custody.Reserved(_) -> "reserved"
      custody.Busy -> "busy"
      other -> string.inspect(other)
    }
  }
  let results = support.spawn_collect(list.repeat(attempt, 12), 10_000)
  assert list.count(results, fn(r) { r == "reserved" }) == 1
  assert list.count(results, fn(r) { r == "busy" }) == 11
}
