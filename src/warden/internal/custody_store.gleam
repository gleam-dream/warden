//// Built-in session custody owner.
////
//// One actor owns installed sessions and their token material. Installation
//// is idempotent per command identifier: repeating an accepted command
//// returns the same reference and revision. Refresh is serialised per
//// session generation through reservation: only a newly issued dispatch
//// authorises a provider call; while it is outstanding, other callers are
//// told the session is busy. Settlement records a definite outcome
//// (no-send releases the generation, rejection revokes refresh, an uncertain
//// outcome quarantines it). Publication commits new material and advances the
//// revision atomically, and repeating an accepted publication command
//// returns the same receipt without calling the provider again.
////
//// This store is in memory: sessions do not survive a restart of the owner.
//// Durable custody is an application responsibility (see docs).

import gleam/dict.{type Dict}
import gleam/erlang/process.{type Subject}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/otp/actor
import warden/internal/call.{type CallError}
import warden/internal/fifo.{type Fifo}

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

pub type Evidence {
  Evidence(nonce: String, auth_time: Option(Int))
}

pub type Install(identity) {
  Install(
    command_id: String,
    /// When the command was created (Warden's clock, seconds). Replays of
    /// commands at or before the history horizon are refused.
    issued_at: Int,
    provider: String,
    identity: identity,
    evidence: Evidence,
    tokens: Tokens,
  )
}

pub type Receipt {
  Receipt(command_id: String, reference: String, revision: Int)
}

/// Session lifetimes in the store clock's seconds (monotonic in production).
pub type Lifetime {
  Lifetime(absolute: Int, idle: Int)
}

pub type InstallReply {
  /// Installed now, or the receipt of an earlier identical installation.
  Installed(Receipt)
  /// The command was installed and its session has since been removed.
  InstallEnded
  /// The command is older than the retained history; it is neither
  /// confirmed nor installed again.
  InstallExpired
}

pub type Snapshot(identity) {
  Snapshot(
    reference: String,
    provider: String,
    identity: identity,
    evidence: Evidence,
    tokens: Tokens,
    revision: Int,
  )
}

pub type Dispatch(identity) {
  Dispatch(
    reference: String,
    dispatch_id: Int,
    command_id: String,
    revision: Int,
    refresh_token: String,
    identity: identity,
    evidence: Evidence,
    scopes: List(String),
  )
}

pub type Reservation(identity) {
  Reserved(Dispatch(identity))
  ReservationMissing
  ReservationStale
  ReservationBusy
  ReservationQuarantined
  ReservationNoRefreshToken
  ReservationRevoked
  ReservationProviderMismatch
}

pub type Settlement {
  SettleNotSent
  SettleRejected
  SettleQuarantine
}

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
    dispatch_id: Int,
    command_id: String,
    update: Update,
  )
}

pub type PublishReply {
  Published(Receipt)
  PublishRejected
}

/// The outcome of removing a session by reference. Removal ignores the
/// revision: a session ends whatever refreshes happened since it was read.
pub type Removal(identity) {
  /// The session was live and is now removed; its last snapshot.
  Removed(Snapshot(identity))
  /// No live session had that reference (unknown, already removed or
  /// expired; an expired entry is evicted).
  RemovalMissing
  /// The session belongs to another provider configuration; it is kept.
  RemovalForeign
}

pub type SettleReply {
  Settled
  SettleMismatch
}

type RefreshState {
  Idle
  /// A dispatch in flight; `holder` monitors the process performing it.
  Outstanding(dispatch_id: Int, command_id: String, holder: process.Monitor)
  /// The dispatching process died before settling: the provider may have
  /// rotated the token. New reservations are refused as quarantined; the
  /// dispatch's own publication recovery is still accepted.
  Orphaned(dispatch_id: Int, command_id: String)
  Quarantined(command_id: String)
  Revoked
}

type Entry(identity) {
  Entry(
    provider: String,
    identity: identity,
    evidence: Evidence,
    tokens: Tokens,
    revision: Int,
    refresh: RefreshState,
    /// Store-clock times of installation and of the latest use.
    created_at: Int,
    last_used_at: Int,
  )
}

pub opaque type Message(identity) {
  InstallMsg(Install(identity), Subject(InstallReply))
  GetMsg(String, Subject(Result(Snapshot(identity), Nil)))
  ReserveMsg(
    reference: String,
    provider: String,
    revision: Int,
    command_id: String,
    holder: process.Pid,
    reply: Subject(Reservation(identity)),
  )
  SettleMsg(
    reference: String,
    dispatch_id: Int,
    settlement: Settlement,
    reply: Subject(SettleReply),
  )
  PublishMsg(Publish, Subject(PublishReply))
  RemoveMsg(String, String, Subject(Removal(identity)))
  HolderDown(process.Down)
  SweepMsg(Subject(Nil))
  SweepTick(Subject(Message(identity)))
  CountMsg(Subject(Int))
  DelayRepliesMsg(DelayedReply, Int, Subject(Nil))
}

type State(identity) {
  State(
    entries: Dict(String, Entry(identity)),
    installs: Dict(String, Receipt),
    /// Installed commands, oldest first: #(issued_at, command_id).
    install_order: Fifo(#(Int, String)),
    /// The latest `issued_at` evicted from `installs`; replays at or before
    /// it cannot be told apart from new commands and are refused.
    horizon: Option(Int),
    publications: Dict(String, Receipt),
    new_reference: fn() -> String,
    clock: fn() -> Int,
    lifetime: Lifetime,
    next_dispatch: Int,
    history_limit: Int,
    reply_delay: #(DelayedReply, Int),
  )
}

/// Test support: which replies to delay.
pub type DelayedReply {
  DelayInstall
  DelayPublish
  DelayNothing
}

pub type Store(identity) {
  Store(subject: Subject(Message(identity)), timeout: Int)
}

pub fn start(
  new_reference new_reference: fn() -> String,
  history_limit history_limit: Int,
  clock clock: fn() -> Int,
  lifetime lifetime: Lifetime,
  name name: process.Name(Message(identity)),
) -> actor.StartResult(Subject(Message(identity))) {
  actor.new_with_initialiser(1000, fn(self) {
    // Receive DOWN messages for dispatching processes as well.
    let selector =
      process.new_selector()
      |> process.select(self)
      |> process.select_monitors(HolderDown)
    process.send_after(self, sweep_interval_ms, SweepTick(self))
    actor.initialised(initial(new_reference, history_limit, clock, lifetime))
    |> actor.selecting(selector)
    |> actor.returning(self)
    |> Ok
  })
  |> actor.named(name)
  |> actor.on_message(handle)
  |> actor.start
}

fn initial(
  new_reference: fn() -> String,
  history_limit: Int,
  clock: fn() -> Int,
  lifetime: Lifetime,
) -> State(identity) {
  State(
    entries: dict.new(),
    installs: dict.new(),
    install_order: fifo.new(),
    horizon: None,
    publications: dict.new(),
    new_reference:,
    clock:,
    lifetime:,
    next_dispatch: 1,
    history_limit:,
    reply_delay: #(DelayNothing, 0),
  )
}

fn reply(
  state: State(identity),
  kind: DelayedReply,
  subject: Subject(a),
  value: a,
) -> Nil {
  case state.reply_delay {
    #(delayed, delay) if delayed == kind && delay > 0 -> process.sleep(delay)
    _ -> Nil
  }
  process.send(subject, value)
}

fn handle(
  state: State(identity),
  message: Message(identity),
) -> actor.Next(State(identity), Message(identity)) {
  case message {
    InstallMsg(command, subject) ->
      case
        dict.get(state.installs, command.command_id),
        is_before_horizon(state.horizon, command.issued_at)
      {
        // A replay: the same receipt while the session lives.
        Ok(receipt), _ -> {
          let outcome = case dict.has_key(state.entries, receipt.reference) {
            True -> Installed(receipt)
            False -> InstallEnded
          }
          reply(state, DelayInstall, subject, outcome)
          actor.continue(state)
        }
        Error(Nil), True -> {
          reply(state, DelayInstall, subject, InstallExpired)
          actor.continue(state)
        }
        Error(Nil), False -> {
          let reference = state.new_reference()
          let receipt = Receipt(command.command_id, reference, 1)
          let entry =
            Entry(
              provider: command.provider,
              identity: command.identity,
              evidence: command.evidence,
              tokens: command.tokens,
              revision: 1,
              refresh: Idle,
              created_at: state.clock(),
              last_used_at: state.clock(),
            )
          let state =
            State(
              ..state,
              entries: dict.insert(state.entries, reference, entry),
              installs: dict.insert(state.installs, command.command_id, receipt),
              install_order: fifo.push(state.install_order, #(
                command.issued_at,
                command.command_id,
              )),
            )
            |> evict_installs
          reply(state, DelayInstall, subject, Installed(receipt))
          actor.continue(state)
        }
      }
    GetMsg(reference, subject) -> {
      let state = use_entry(state, reference)
      let result = case dict.get(state.entries, reference) {
        Ok(entry) ->
          Ok(Snapshot(
            reference:,
            provider: entry.provider,
            identity: entry.identity,
            evidence: entry.evidence,
            tokens: entry.tokens,
            revision: entry.revision,
          ))
        Error(Nil) -> Error(Nil)
      }
      reply(state, DelayNothing, subject, result)
      actor.continue(state)
    }
    ReserveMsg(reference, provider, revision, command_id, holder, subject) -> {
      let state = use_entry(state, reference)
      let #(result, state) =
        reserve(state, reference, provider, revision, command_id, holder)
      reply(state, DelayNothing, subject, result)
      actor.continue(state)
    }
    SettleMsg(reference, dispatch_id, settlement, subject) -> {
      let #(result, state) = settle(state, reference, dispatch_id, settlement)
      reply(state, DelayNothing, subject, result)
      actor.continue(state)
    }
    PublishMsg(command, subject) -> {
      let state = use_entry(state, command.reference)
      let #(result, state) = publish(state, command)
      reply(state, DelayPublish, subject, result)
      actor.continue(state)
    }
    RemoveMsg(reference, provider, subject) -> {
      let state = use_entry(state, reference)
      let #(result, state) = case dict.get(state.entries, reference) {
        Error(Nil) -> #(RemovalMissing, state)
        Ok(entry) if entry.provider != provider -> #(RemovalForeign, state)
        Ok(entry) -> #(
          Removed(Snapshot(
            reference:,
            provider: entry.provider,
            identity: entry.identity,
            evidence: entry.evidence,
            tokens: entry.tokens,
            revision: entry.revision,
          )),
          State(..state, entries: dict.delete(state.entries, reference)),
        )
      }
      reply(state, DelayNothing, subject, result)
      actor.continue(state)
    }
    HolderDown(down) -> actor.continue(orphan(state, down))
    SweepMsg(subject) -> {
      let state = sweep_expired(state)
      process.send(subject, Nil)
      actor.continue(state)
    }
    SweepTick(self) -> {
      process.send_after(self, sweep_interval_ms, SweepTick(self))
      actor.continue(sweep_expired(state))
    }
    CountMsg(subject) -> {
      process.send(subject, dict.size(state.entries))
      actor.continue(state)
    }
    DelayRepliesMsg(kind, delay, subject) -> {
      process.send(subject, Nil)
      actor.continue(State(..state, reply_delay: #(kind, delay)))
    }
  }
}

/// How often expired sessions are evicted when nobody uses them.
const sweep_interval_ms = 60_000

fn expired(state: State(identity), entry: Entry(identity), now: Int) -> Bool {
  now - entry.created_at >= state.lifetime.absolute
  || now - entry.last_used_at >= state.lifetime.idle
}

/// A use of a session: evict it if it has expired, otherwise restart its
/// idle period.
fn use_entry(state: State(identity), reference: String) -> State(identity) {
  let now = state.clock()
  case dict.get(state.entries, reference) {
    Error(Nil) -> state
    Ok(entry) ->
      case expired(state, entry, now) {
        True -> State(..state, entries: dict.delete(state.entries, reference))
        False ->
          State(
            ..state,
            entries: dict.insert(
              state.entries,
              reference,
              Entry(..entry, last_used_at: now),
            ),
          )
      }
  }
}

/// Evict every expired session, with its tokens.
fn sweep_expired(state: State(identity)) -> State(identity) {
  let now = state.clock()
  State(
    ..state,
    entries: dict.filter(state.entries, fn(_, entry) {
      !expired(state, entry, now)
    }),
  )
}

/// The process holding a reservation died: orphan its generation.
fn orphan(state: State(identity), down: process.Down) -> State(identity) {
  let entries =
    dict.map_values(state.entries, fn(_, entry) {
      case entry.refresh {
        Outstanding(dispatch_id:, command_id:, holder:)
          if holder == down.monitor
        -> Entry(..entry, refresh: Orphaned(dispatch_id:, command_id:))
        _ -> entry
      }
    })
  State(..state, entries:)
}

fn reserve(
  state: State(identity),
  reference: String,
  provider: String,
  revision: Int,
  command_id: String,
  holder: process.Pid,
) -> #(Reservation(identity), State(identity)) {
  case dict.get(state.entries, reference) {
    Error(Nil) -> #(ReservationMissing, state)
    Ok(entry) if entry.provider != provider -> #(
      ReservationProviderMismatch,
      state,
    )
    Ok(entry) ->
      case entry.refresh {
        Quarantined(_) | Orphaned(..) -> #(ReservationQuarantined, state)
        Revoked -> #(ReservationRevoked, state)
        Outstanding(..) -> #(ReservationBusy, state)
        Idle if entry.revision != revision -> #(ReservationStale, state)
        Idle ->
          case entry.tokens.refresh_token {
            None -> #(ReservationNoRefreshToken, state)
            Some(refresh_token) -> {
              let dispatch_id = state.next_dispatch
              let entry =
                Entry(
                  ..entry,
                  refresh: Outstanding(
                    dispatch_id,
                    command_id,
                    process.monitor(holder),
                  ),
                )
              let dispatch =
                Dispatch(
                  reference:,
                  dispatch_id:,
                  command_id:,
                  revision: entry.revision,
                  refresh_token:,
                  identity: entry.identity,
                  evidence: entry.evidence,
                  scopes: entry.tokens.scopes,
                )
              #(
                Reserved(dispatch),
                State(
                  ..state,
                  entries: dict.insert(state.entries, reference, entry),
                  next_dispatch: dispatch_id + 1,
                ),
              )
            }
          }
      }
  }
}

fn settle(
  state: State(identity),
  reference: String,
  dispatch_id: Int,
  settlement: Settlement,
) -> #(SettleReply, State(identity)) {
  case dict.get(state.entries, reference) {
    Ok(Entry(refresh: Outstanding(id, command_id, holder), ..) as entry)
      if id == dispatch_id
    -> {
      process.demonitor_process(holder)
      let refresh = case settlement {
        SettleNotSent -> Idle
        SettleRejected -> Revoked
        SettleQuarantine -> Quarantined(command_id)
      }
      let entries =
        dict.insert(state.entries, reference, Entry(..entry, refresh:))
      #(Settled, State(..state, entries:))
    }
    _ -> #(SettleMismatch, state)
  }
}

fn publish(
  state: State(identity),
  command: Publish,
) -> #(PublishReply, State(identity)) {
  case dict.get(state.publications, command.command_id) {
    Ok(receipt) -> #(Published(receipt), state)
    Error(Nil) ->
      case dict.get(state.entries, command.reference) {
        Ok(Entry(refresh: Outstanding(dispatch_id: id, ..), ..) as entry)
          | Ok(Entry(refresh: Orphaned(dispatch_id: id, ..), ..) as entry)
          if id == command.dispatch_id
        -> {
          case entry.refresh {
            Outstanding(holder:, ..) -> process.demonitor_process(holder)
            _ -> Nil
          }
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
          let receipt = Receipt(command.command_id, command.reference, revision)
          let entry = Entry(..entry, tokens:, revision:, refresh: Idle)
          #(
            Published(receipt),
            State(
              ..state,
              entries: dict.insert(state.entries, command.reference, entry),
              publications: bounded_insert(
                state.publications,
                command.command_id,
                receipt,
                state.history_limit,
              ),
            ),
          )
        }
        _ -> #(PublishRejected, state)
      }
  }
}

/// Command history is bounded; beyond the limit an arbitrary half is
/// dropped. A dropped command can no longer be recovered by replay, which
/// surfaces as a typed mismatch rather than a second installation.
fn is_before_horizon(horizon: Option(Int), issued_at: Int) -> Bool {
  case horizon {
    Some(horizon) -> issued_at <= horizon
    None -> False
  }
}

/// Keep at most `history_limit` install receipts, evicting the oldest and
/// advancing the horizon past them.
fn evict_installs(state: State(identity)) -> State(identity) {
  case fifo.size(state.install_order) > state.history_limit {
    False -> state
    True ->
      case fifo.pop(state.install_order) {
        Error(Nil) -> state
        Ok(#(#(issued_at, command_id), rest)) ->
          evict_installs(
            State(
              ..state,
              installs: dict.delete(state.installs, command_id),
              install_order: rest,
              horizon: Some(case state.horizon {
                Some(horizon) -> int.max(horizon, issued_at)
                None -> issued_at
              }),
            ),
          )
      }
  }
}

fn bounded_insert(
  history: Dict(String, Receipt),
  key: String,
  value: Receipt,
  limit: Int,
) -> Dict(String, Receipt) {
  let history = case dict.size(history) >= limit {
    True ->
      history
      |> dict.to_list
      |> list.drop(int.max(1, limit / 2))
      |> dict.from_list
    False -> history
  }
  dict.insert(history, key, value)
}

// ---------------------------------------------------------------------------
// Client functions

pub fn install(
  store: Store(identity),
  command: Install(identity),
) -> Result(InstallReply, CallError) {
  call.call(store.subject, store.timeout, InstallMsg(command, _))
}

pub fn get(
  store: Store(identity),
  reference: String,
) -> Result(Result(Snapshot(identity), Nil), CallError) {
  call.call(store.subject, store.timeout, GetMsg(reference, _))
}

pub fn reserve_refresh(
  store: Store(identity),
  reference: String,
  provider: String,
  revision: Int,
  command_id: String,
) -> Result(Reservation(identity), CallError) {
  // The caller of reserve_refresh dispatches the request; the custody
  // owner monitors it (call.call runs through a proxy process).
  let holder = process.self()
  call.call(store.subject, store.timeout, ReserveMsg(
    reference,
    provider,
    revision,
    command_id,
    holder,
    _,
  ))
}

pub fn settle_refresh(
  store: Store(identity),
  reference: String,
  dispatch_id: Int,
  settlement: Settlement,
) -> Result(SettleReply, CallError) {
  call.call(store.subject, store.timeout, SettleMsg(
    reference,
    dispatch_id,
    settlement,
    _,
  ))
}

pub fn publish_refresh(
  store: Store(identity),
  command: Publish,
) -> Result(PublishReply, CallError) {
  call.call(store.subject, store.timeout, PublishMsg(command, _))
}

/// Remove a session by reference, regardless of its revision, in one step
/// of the custody owner, returning the snapshot it held.
pub fn remove(
  store: Store(identity),
  reference: String,
  provider: String,
) -> Result(Removal(identity), CallError) {
  call.call(store.subject, store.timeout, RemoveMsg(reference, provider, _))
}

/// Test support: delay replies of one kind by `delay` milliseconds after the
/// state change is committed, simulating a lost acknowledgement.
@internal
pub fn delay_replies(
  store: Store(identity),
  kind: DelayedReply,
  delay: Int,
) -> Result(Nil, CallError) {
  call.call(store.subject, store.timeout, DelayRepliesMsg(kind, delay, _))
}

/// Test support: evict expired sessions now.
@internal
pub fn sweep(store: Store(identity)) -> Result(Nil, CallError) {
  call.call(store.subject, store.timeout, SweepMsg)
}

/// Test support: the number of sessions held.
@internal
pub fn entry_count(store: Store(identity)) -> Result(Int, CallError) {
  call.call(store.subject, store.timeout, CountMsg)
}
