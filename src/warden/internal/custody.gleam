//// Session custody over a record store.
////
//// One sealed record per session, keyed by a digest of its reference. Every
//// transition is a compare-and-set on the record's version, so any number of
//// processes or nodes may share one store:
////
//// - `install` inserts the record a login command names; resubmitting the
////   same command returns the same receipt, and a command older than the
////   retention horizon is refused;
//// - `reserve` marks the session's refresh generation as dispatched by one
////   caller, with a lease. Only a fresh reservation authorises a provider
////   call. When the lease expires before settlement the generation is
////   quarantined (`Orphaned`), never released: the provider may have rotated
////   the refresh token;
//// - `settle` records a definite outcome: not sent releases the generation,
////   rejection revokes refresh, anything uncertain quarantines it;
//// - `publish` installs refreshed material and advances the revision; a
////   resubmitted publication returns its receipt;
//// - `remove` replaces the session with a tombstone kept for the retention
////   horizon, so a late install recovery cannot bring it back.
////
//// Lifetimes are wall-clock Unix seconds, because a durable store outlives
//// any one node's monotonic clock.

import gleam/bit_array
import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/time/timestamp
import warden/internal/port.{type Port}
import warden/internal/sealed.{type Keys}
import warden/internal/secure
import warden/store.{type StoreError, Record}

const kind = "warden.session.v1"

/// How many compare-and-set conflicts a transition retries.
const attempts = 8

pub type Tokens {
  Tokens(
    access_token: String,
    token_type: String,
    expires_at: Option(Int),
    refresh_token: Option(String),
    id_token: Option(String),
    scopes: List(String),
  )
}

/// The verified identity as sealed in custody: the login ID token's issuer,
/// subject and claims (JSON text).
pub type Identity {
  Identity(issuer: String, subject: String, claims: String)
}

pub type Evidence {
  Evidence(nonce: String, auth_time: Option(Int))
}

pub type RefreshState {
  Idle
  Outstanding(dispatch_id: String, command_id: String, lease_until: Int)
  /// The lease ran out before settlement: quarantined, though the dispatch's
  /// own publication is still accepted.
  Orphaned(dispatch_id: String, command_id: String)
  Quarantined(command_id: String, reason: String)
  Revoked
}

pub type Entry {
  Entry(
    provider: String,
    install: String,
    identity: Identity,
    evidence: Evidence,
    tokens: Tokens,
    revision: Int,
    refresh: RefreshState,
    created_at: Int,
    last_used_at: Int,
    /// Recent publications: #(command_id, revision).
    publications: List(#(String, Int)),
  )
}

type Stored {
  Live(Entry)
  Ended(provider: String, install: String)
}

pub type Custody {
  Custody(
    port: Port,
    keys: Keys,
    clock: fn() -> Int,
    absolute: Int,
    idle: Int,
    /// How long tombstones and install receipts are kept, and how old an
    /// install command may be.
    retention: Int,
    /// The in-memory store's epoch, which prefixes its references.
    epoch: Option(fn() -> Result(String, StoreError)),
  )
}

pub type Snapshot {
  Snapshot(reference: String, entry: Entry, version: Int)
}

pub type ReadError {
  /// No live session: unknown, logged out or expired.
  Missing
  /// The in-memory store restarted since the reference was issued.
  Lost
  /// The record did not open: tampered, or sealed with an unknown key.
  Unreadable
  Unavailable
}

// ---------------------------------------------------------------------------
// References and keys

/// A new session reference: 256 random bits, prefixed with the in-memory
/// store's epoch when it answers.
pub fn new_reference(custody: Custody) -> String {
  let random = secure.random_token(32)
  case option.map(custody.epoch, fn(epoch) { epoch() }) {
    Some(Ok(epoch)) -> epoch <> "." <> random
    _ -> random
  }
}

fn key(reference: String) -> String {
  "session:" <> secure.sha256_hex(reference)
}

fn record_expiry(custody: Custody, entry: Entry) -> Int {
  let lifetime =
    int.min(
      entry.created_at + custody.absolute,
      entry.last_used_at + custody.idle,
    )
  int.max(lifetime, entry.created_at + custody.retention)
}

fn expired(custody: Custody, entry: Entry, now: Int) -> Bool {
  now >= entry.created_at + custody.absolute
  || now >= entry.last_used_at + custody.idle
}

// ---------------------------------------------------------------------------
// Reading

fn read(
  custody: Custody,
  reference: String,
) -> Result(Option(#(Stored, Int)), ReadError) {
  use found <- result.try(
    port.get(custody.port, key(reference))
    |> result.replace_error(Unavailable),
  )
  case found {
    None -> Ok(None)
    Some(record) ->
      open(custody, key(reference), record.version, record.sealed)
      |> result.map(fn(stored) { Some(#(stored, record.version)) })
      |> result.replace_error(Unreadable)
  }
}

fn missing(custody: Custody, reference: String) -> ReadError {
  case custody.epoch, string.split_once(reference, ".") {
    Some(epoch), Ok(#(prefix, _)) ->
      case epoch() {
        Ok(current) if current != prefix -> Lost
        _ -> Missing
      }
    _, _ -> Missing
  }
}

/// The live session for `reference`. A use restarts its idle period; the
/// write is coalesced (at most once per `granularity` seconds) and its
/// failure ignored.
pub fn get(custody: Custody, reference: String) -> Result(Snapshot, ReadError) {
  let now = custody.clock()
  case read(custody, reference) {
    Error(error) -> Error(error)
    Ok(Some(#(Live(entry), version))) ->
      case expired(custody, entry, now) {
        True -> Error(Missing)
        False -> Ok(touch(custody, reference, entry, version, now))
      }
    Ok(Some(#(Ended(..), _))) -> Error(Missing)
    Ok(None) -> Error(missing(custody, reference))
  }
}

fn touch(
  custody: Custody,
  reference: String,
  entry: Entry,
  version: Int,
  now: Int,
) -> Snapshot {
  let granularity = int.clamp(custody.idle / 10, 1, 60)
  case now - entry.last_used_at >= granularity {
    False -> Snapshot(reference:, entry:, version:)
    True -> {
      let touched = Entry(..entry, last_used_at: now)
      case write(custody, reference, Live(touched), version) {
        Ok(True) -> Snapshot(reference:, entry: touched, version: version + 1)
        _ -> Snapshot(reference:, entry:, version:)
      }
    }
  }
}

fn write(
  custody: Custody,
  reference: String,
  stored: Stored,
  version: Int,
) -> Result(Bool, StoreError) {
  let next = version + 1
  let expires_at = case stored {
    Live(entry) -> record_expiry(custody, entry)
    Ended(..) -> custody.clock() + custody.retention
  }
  port.put(
    custody.port,
    Record(
      key: key(reference),
      version: next,
      expires_at: timestamp.from_unix_seconds(expires_at),
      sealed: seal(custody, key(reference), next, stored),
    ),
    Some(version),
  )
}

/// Apply `step` to the current record with compare-and-set, retrying on a
/// conflicting write.
fn transition(
  custody: Custody,
  reference: String,
  remaining: Int,
  conflict: a,
  failure: fn(ReadError) -> a,
  unknown: a,
  step: fn(Option(Stored), Int) -> Step(a),
) -> a {
  case read(custody, reference) {
    Error(error) -> failure(error)
    Ok(found) -> {
      let #(current, version) = case found {
        Some(#(stored, version)) -> #(Some(stored), version)
        None -> #(None, 0)
      }
      case step(current, version) {
        Done(answer) -> answer
        Write(stored, answer) ->
          case write(custody, reference, stored, version) {
            Ok(True) -> answer
            Ok(False) if remaining > 1 ->
              transition(
                custody,
                reference,
                remaining - 1,
                conflict,
                failure,
                unknown,
                step,
              )
            Ok(False) -> conflict
            Error(store.StoreUnavailable) -> failure(Unavailable)
            Error(_) -> unknown
          }
      }
    }
  }
}

type Step(a) {
  Write(Stored, a)
  Done(a)
}

// ---------------------------------------------------------------------------
// Install

pub type Install {
  Install(
    reference: String,
    command_id: String,
    /// Unix seconds when the command was created.
    issued_at: Int,
    provider: String,
    identity: Identity,
    evidence: Evidence,
    tokens: Tokens,
  )
}

pub type InstallReply {
  /// Installed now, or the receipt of an earlier identical installation.
  Installed(revision: Int)
  /// The command was installed and its session has since ended.
  InstallEnded
  /// The command is older than the retention horizon.
  InstallExpired
  /// The store may or may not have installed it.
  InstallUnknown
}

pub fn install(custody: Custody, command: Install) -> InstallReply {
  let now = custody.clock()
  case now - command.issued_at > custody.retention {
    True -> InstallExpired
    False -> {
      let entry =
        Entry(
          provider: command.provider,
          install: command.command_id,
          identity: command.identity,
          evidence: command.evidence,
          tokens: command.tokens,
          revision: 1,
          refresh: Idle,
          created_at: command.issued_at,
          last_used_at: now,
          publications: [],
        )
      let record =
        Record(
          key: key(command.reference),
          version: 1,
          expires_at: timestamp.from_unix_seconds(record_expiry(custody, entry)),
          sealed: seal(custody, key(command.reference), 1, Live(entry)),
        )
      case port.put(custody.port, record, None) {
        Ok(True) -> Installed(1)
        Ok(False) ->
          case read(custody, command.reference) {
            Ok(Some(#(Live(existing), _)))
              if existing.install == command.command_id
            -> Installed(existing.revision)
            Ok(Some(_)) -> InstallEnded
            Ok(None) -> InstallUnknown
            Error(_) -> InstallUnknown
          }
        Error(_) -> InstallUnknown
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Refresh reservation

pub type Dispatch {
  Dispatch(
    reference: String,
    dispatch_id: String,
    command_id: String,
    revision: Int,
    refresh_token: String,
    identity: Identity,
    evidence: Evidence,
    scopes: List(String),
  )
}

pub type Reservation {
  Reserved(Dispatch)
  /// Another caller holds a live reservation.
  Busy
  /// The session's revision moved past the caller's: the current snapshot.
  Stale(Snapshot)
  ReservationQuarantined(reason: String)
  ReservationRevoked
  /// The session has no refresh token: the current snapshot.
  NoRefreshToken(Snapshot)
  ReservationFailed(ReadError)
  /// The store may or may not have recorded the reservation.
  ReservationUnknown
}

const orphaned_reason = "refresher_lost"

pub fn reserve(
  custody: Custody,
  reference: String,
  provider: String,
  revision: Int,
  command_id: String,
  lease_seconds: Int,
) -> Reservation {
  let now = custody.clock()
  use current, version <- transition(
    custody,
    reference,
    attempts,
    ReservationUnknown,
    ReservationFailed,
    ReservationUnknown,
  )
  case current {
    None -> Done(ReservationFailed(missing(custody, reference)))
    Some(Ended(..)) -> Done(ReservationFailed(Missing))
    Some(Live(entry)) ->
      case entry.provider == provider, expired(custody, entry, now) {
        False, _ -> Done(ReservationFailed(Missing))
        _, True -> Done(ReservationFailed(Missing))
        True, False -> {
          let snapshot = Snapshot(reference:, entry:, version:)
          case entry.refresh {
            Outstanding(dispatch_id:, command_id: held, lease_until:)
              if now >= lease_until
            ->
              Write(
                Live(
                  Entry(
                    ..entry,
                    refresh: Orphaned(dispatch_id:, command_id: held),
                  ),
                ),
                ReservationQuarantined(orphaned_reason),
              )
            Outstanding(..) -> Done(Busy)
            Orphaned(..) -> Done(ReservationQuarantined(orphaned_reason))
            Quarantined(reason:, ..) -> Done(ReservationQuarantined(reason))
            Revoked -> Done(ReservationRevoked)
            Idle if entry.revision != revision -> Done(Stale(snapshot))
            Idle ->
              case entry.tokens.refresh_token {
                None -> Done(NoRefreshToken(snapshot))
                Some(refresh_token) -> {
                  let dispatch_id = secure.random_token(18)
                  Write(
                    Live(
                      Entry(
                        ..entry,
                        refresh: Outstanding(
                          dispatch_id:,
                          command_id:,
                          lease_until: now + lease_seconds,
                        ),
                      ),
                    ),
                    Reserved(Dispatch(
                      reference:,
                      dispatch_id:,
                      command_id:,
                      revision: entry.revision,
                      refresh_token:,
                      identity: entry.identity,
                      evidence: entry.evidence,
                      scopes: entry.tokens.scopes,
                    )),
                  )
                }
              }
          }
        }
      }
  }
}

pub type Settlement {
  SettleNotSent
  SettleRejected
  SettleQuarantine(reason: String)
}

/// Record a dispatch's definite outcome. `False` when the store did not
/// confirm it, or the dispatch no longer holds the reservation.
pub fn settle(
  custody: Custody,
  reference: String,
  dispatch_id: String,
  settlement: Settlement,
) -> Bool {
  use current, _ <- transition(
    custody,
    reference,
    attempts,
    False,
    fn(_) { False },
    False,
  )
  case current {
    Some(Live(
      Entry(refresh: Outstanding(dispatch_id: id, command_id:, ..), ..) as entry,
    ))
      if id == dispatch_id
    ->
      Write(
        Live(
          Entry(..entry, refresh: case settlement {
            SettleNotSent -> Idle
            SettleRejected -> Revoked
            SettleQuarantine(reason) -> Quarantined(command_id:, reason:)
          }),
        ),
        True,
      )
    // The lease ran out first: the generation stays quarantined, except that
    // a rejection is recorded as a revocation.
    Some(Live(Entry(refresh: Orphaned(dispatch_id: id, ..), ..) as entry))
      if id == dispatch_id
    ->
      case settlement {
        SettleRejected -> Write(Live(Entry(..entry, refresh: Revoked)), True)
        _ -> Done(False)
      }
    _ -> Done(False)
  }
}

// ---------------------------------------------------------------------------
// Publication

pub type Replace(a) {
  Retain
  ReplaceWith(a)
}

pub type Update {
  Update(
    access_token: String,
    token_type: String,
    expires_at: Option(Int),
    refresh_token: Replace(String),
    id_token: Replace(String),
    scopes: Replace(List(String)),
  )
}

pub type Publish {
  Publish(
    reference: String,
    provider: String,
    dispatch_id: String,
    command_id: String,
    update: Update,
  )
}

pub type PublishReply {
  Published(Snapshot)
  PublishRejected
  PublishFailed(ReadError)
  PublishUnknown
}

pub fn publish(custody: Custody, command: Publish) -> PublishReply {
  let reference = command.reference
  use current, version <- transition(
    custody,
    reference,
    attempts,
    PublishUnknown,
    PublishFailed,
    PublishUnknown,
  )
  case current {
    None -> Done(PublishFailed(missing(custody, reference)))
    Some(Ended(..)) -> Done(PublishFailed(Missing))
    Some(Live(entry)) if entry.provider != command.provider ->
      Done(PublishFailed(Missing))
    Some(Live(entry)) ->
      case list.key_find(entry.publications, command.command_id) {
        // Already published: the current snapshot is the receipt.
        Ok(_) -> Done(Published(Snapshot(reference:, entry:, version:)))
        Error(Nil) ->
          case entry.refresh {
            Outstanding(dispatch_id: id, ..)
              | Orphaned(dispatch_id: id, ..)
              if id == command.dispatch_id
            -> {
              let update = command.update
              let tokens =
                Tokens(
                  access_token: update.access_token,
                  token_type: update.token_type,
                  expires_at: update.expires_at,
                  refresh_token: case update.refresh_token {
                    Retain -> entry.tokens.refresh_token
                    ReplaceWith(token) -> Some(token)
                  },
                  id_token: case update.id_token {
                    Retain -> entry.tokens.id_token
                    ReplaceWith(token) -> Some(token)
                  },
                  scopes: case update.scopes {
                    Retain -> entry.tokens.scopes
                    ReplaceWith(scopes) -> scopes
                  },
                )
              let revision = entry.revision + 1
              let published =
                Entry(
                  ..entry,
                  tokens:,
                  revision:,
                  refresh: Idle,
                  last_used_at: custody.clock(),
                  publications: list.take(
                    [#(command.command_id, revision), ..entry.publications],
                    8,
                  ),
                )
              Write(
                Live(published),
                Published(Snapshot(
                  reference:,
                  entry: published,
                  version: version + 1,
                )),
              )
            }
            _ -> Done(PublishRejected)
          }
      }
  }
}

// ---------------------------------------------------------------------------
// Removal

pub type Removal {
  Removed(Snapshot)
  RemovalMissing
  RemovalForeign
  RemovalFailed
}

/// End a session by reference, whatever its revision, leaving a tombstone.
pub fn remove(
  custody: Custody,
  reference: String,
  provider: String,
) -> Removal {
  let now = custody.clock()
  use current, version <- transition(
    custody,
    reference,
    attempts,
    RemovalFailed,
    fn(error) {
      case error {
        Missing | Lost -> RemovalMissing
        _ -> RemovalFailed
      }
    },
    RemovalFailed,
  )
  case current {
    None | Some(Ended(..)) -> Done(RemovalMissing)
    Some(Live(entry)) if entry.provider != provider -> Done(RemovalForeign)
    Some(Live(entry)) ->
      case expired(custody, entry, now) {
        True -> Done(RemovalMissing)
        False ->
          Write(
            Ended(provider: entry.provider, install: entry.install),
            Removed(Snapshot(reference:, entry:, version:)),
          )
      }
  }
}

// ---------------------------------------------------------------------------
// Sealed encoding

fn seal(
  custody: Custody,
  key: String,
  version: Int,
  stored: Stored,
) -> BitArray {
  sealed.seal(
    custody.keys,
    kind:,
    key:,
    version:,
    plaintext: bit_array.from_string(json.to_string(encode(stored))),
  )
}

fn open(
  custody: Custody,
  key: String,
  version: Int,
  value: BitArray,
) -> Result(Stored, Nil) {
  use plain <- result.try(sealed.open(
    custody.keys,
    kind:,
    key:,
    version:,
    sealed: value,
  ))
  use text <- result.try(bit_array.to_string(plain))
  json.parse(text, stored_decoder()) |> result.replace_error(Nil)
}

fn encode(stored: Stored) -> json.Json {
  case stored {
    Ended(provider:, install:) ->
      json.object([
        #("ended", json.bool(True)),
        #("provider", json.string(provider)),
        #("install", json.string(install)),
      ])
    Live(entry) ->
      json.object([
        #("provider", json.string(entry.provider)),
        #("install", json.string(entry.install)),
        #("issuer", json.string(entry.identity.issuer)),
        #("subject", json.string(entry.identity.subject)),
        #("claims", json.string(entry.identity.claims)),
        #("nonce", json.string(entry.evidence.nonce)),
        #("auth_time", json.nullable(entry.evidence.auth_time, json.int)),
        #("access_token", json.string(entry.tokens.access_token)),
        #("token_type", json.string(entry.tokens.token_type)),
        #("expires_at", json.nullable(entry.tokens.expires_at, json.int)),
        #(
          "refresh_token",
          json.nullable(entry.tokens.refresh_token, json.string),
        ),
        #("id_token", json.nullable(entry.tokens.id_token, json.string)),
        #("scopes", json.array(entry.tokens.scopes, json.string)),
        #("revision", json.int(entry.revision)),
        #("refresh", encode_refresh(entry.refresh)),
        #("created_at", json.int(entry.created_at)),
        #("last_used_at", json.int(entry.last_used_at)),
        #(
          "publications",
          json.array(entry.publications, fn(p) {
            json.preprocessed_array([json.string(p.0), json.int(p.1)])
          }),
        ),
      ])
  }
}

fn encode_refresh(state: RefreshState) -> json.Json {
  case state {
    Idle -> json.object([#("state", json.string("idle"))])
    Outstanding(dispatch_id:, command_id:, lease_until:) ->
      json.object([
        #("state", json.string("outstanding")),
        #("dispatch", json.string(dispatch_id)),
        #("command", json.string(command_id)),
        #("lease_until", json.int(lease_until)),
      ])
    Orphaned(dispatch_id:, command_id:) ->
      json.object([
        #("state", json.string("orphaned")),
        #("dispatch", json.string(dispatch_id)),
        #("command", json.string(command_id)),
      ])
    Quarantined(command_id:, reason:) ->
      json.object([
        #("state", json.string("quarantined")),
        #("command", json.string(command_id)),
        #("reason", json.string(reason)),
      ])
    Revoked -> json.object([#("state", json.string("revoked"))])
  }
}

fn stored_decoder() -> decode.Decoder(Stored) {
  let ended = {
    use _ <- decode.field("ended", decode.bool)
    use provider <- decode.field("provider", decode.string)
    use install <- decode.field("install", decode.string)
    decode.success(Ended(provider:, install:))
  }
  let live = {
    use provider <- decode.field("provider", decode.string)
    use install <- decode.field("install", decode.string)
    use issuer <- decode.field("issuer", decode.string)
    use subject <- decode.field("subject", decode.string)
    use claims <- decode.field("claims", decode.string)
    use nonce <- decode.field("nonce", decode.string)
    use auth_time <- decode.field("auth_time", decode.optional(decode.int))
    use access_token <- decode.field("access_token", decode.string)
    use token_type <- decode.field("token_type", decode.string)
    use expires_at <- decode.field("expires_at", decode.optional(decode.int))
    use refresh_token <- decode.field(
      "refresh_token",
      decode.optional(decode.string),
    )
    use id_token <- decode.field("id_token", decode.optional(decode.string))
    use scopes <- decode.field("scopes", decode.list(decode.string))
    use revision <- decode.field("revision", decode.int)
    use refresh <- decode.field("refresh", refresh_decoder())
    use created_at <- decode.field("created_at", decode.int)
    use last_used_at <- decode.field("last_used_at", decode.int)
    use publications <- decode.field(
      "publications",
      decode.list({
        use command <- decode.field(0, decode.string)
        use revision <- decode.field(1, decode.int)
        decode.success(#(command, revision))
      }),
    )
    decode.success(
      Live(Entry(
        provider:,
        install:,
        identity: Identity(issuer:, subject:, claims:),
        evidence: Evidence(nonce:, auth_time:),
        tokens: Tokens(
          access_token:,
          token_type:,
          expires_at:,
          refresh_token:,
          id_token:,
          scopes:,
        ),
        revision:,
        refresh:,
        created_at:,
        last_used_at:,
        publications:,
      )),
    )
  }
  decode.one_of(ended, [live])
}

fn refresh_decoder() -> decode.Decoder(RefreshState) {
  use state <- decode.field("state", decode.string)
  case state {
    "idle" -> decode.success(Idle)
    "revoked" -> decode.success(Revoked)
    "outstanding" -> {
      use dispatch_id <- decode.field("dispatch", decode.string)
      use command_id <- decode.field("command", decode.string)
      use lease_until <- decode.field("lease_until", decode.int)
      decode.success(Outstanding(dispatch_id:, command_id:, lease_until:))
    }
    "orphaned" -> {
      use dispatch_id <- decode.field("dispatch", decode.string)
      use command_id <- decode.field("command", decode.string)
      decode.success(Orphaned(dispatch_id:, command_id:))
    }
    "quarantined" -> {
      use command_id <- decode.field("command", decode.string)
      use reason <- decode.field("reason", decode.string)
      decode.success(Quarantined(command_id:, reason:))
    }
    _ -> decode.failure(Idle, "refresh state")
  }
}
