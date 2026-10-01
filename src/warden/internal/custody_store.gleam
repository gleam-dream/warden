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
    provider: String,
    identity: identity,
    evidence: Evidence,
    tokens: Tokens,
  )
}

pub type Receipt {
  Receipt(command_id: String, reference: String, revision: Int)
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

pub type SettleReply {
  Settled
  SettleMismatch
}

type RefreshState {
  Idle
  Outstanding(dispatch_id: Int, command_id: String)
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
  )
}

pub opaque type Message(identity) {
  InstallMsg(Install(identity), Subject(Receipt))
  GetMsg(String, Subject(Result(Snapshot(identity), Nil)))
  ReserveMsg(
    reference: String,
    provider: String,
    revision: Int,
    command_id: String,
    reply: Subject(Reservation(identity)),
  )
  SettleMsg(
    reference: String,
    dispatch_id: Int,
    settlement: Settlement,
    reply: Subject(SettleReply),
  )
  PublishMsg(Publish, Subject(PublishReply))
  RemoveMsg(String, Subject(Nil))
  DelayRepliesMsg(DelayedReply, Int, Subject(Nil))
}

type State(identity) {
  State(
    entries: Dict(String, Entry(identity)),
    installs: Dict(String, Receipt),
    publications: Dict(String, Receipt),
    new_reference: fn() -> String,
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
  name name: process.Name(Message(identity)),
) -> actor.StartResult(Subject(Message(identity))) {
  actor.new(
    State(
      entries: dict.new(),
      installs: dict.new(),
      publications: dict.new(),
      new_reference:,
      next_dispatch: 1,
      history_limit:,
      reply_delay: #(DelayNothing, 0),
    ),
  )
  |> actor.named(name)
  |> actor.on_message(handle)
  |> actor.start
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
      case dict.get(state.installs, command.command_id) {
        Ok(receipt) -> {
          reply(state, DelayInstall, subject, receipt)
          actor.continue(state)
        }
        Error(Nil) -> {
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
            )
          let state =
            State(
              ..state,
              entries: dict.insert(state.entries, reference, entry),
              installs: bounded_insert(
                state.installs,
                command.command_id,
                receipt,
                state.history_limit,
              ),
            )
          reply(state, DelayInstall, subject, receipt)
          actor.continue(state)
        }
      }
    GetMsg(reference, subject) -> {
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
    ReserveMsg(reference, provider, revision, command_id, subject) -> {
      let #(result, state) =
        reserve(state, reference, provider, revision, command_id)
      reply(state, DelayNothing, subject, result)
      actor.continue(state)
    }
    SettleMsg(reference, dispatch_id, settlement, subject) -> {
      let #(result, state) = settle(state, reference, dispatch_id, settlement)
      reply(state, DelayNothing, subject, result)
      actor.continue(state)
    }
    PublishMsg(command, subject) -> {
      let #(result, state) = publish(state, command)
      reply(state, DelayPublish, subject, result)
      actor.continue(state)
    }
    RemoveMsg(reference, subject) -> {
      let state = State(..state, entries: dict.delete(state.entries, reference))
      reply(state, DelayNothing, subject, Nil)
      actor.continue(state)
    }
    DelayRepliesMsg(kind, delay, subject) -> {
      process.send(subject, Nil)
      actor.continue(State(..state, reply_delay: #(kind, delay)))
    }
  }
}

fn reserve(
  state: State(identity),
  reference: String,
  provider: String,
  revision: Int,
  command_id: String,
) -> #(Reservation(identity), State(identity)) {
  case dict.get(state.entries, reference) {
    Error(Nil) -> #(ReservationMissing, state)
    Ok(entry) if entry.provider != provider -> #(
      ReservationProviderMismatch,
      state,
    )
    Ok(entry) ->
      case entry.refresh {
        Quarantined(_) -> #(ReservationQuarantined, state)
        Revoked -> #(ReservationRevoked, state)
        Outstanding(..) -> #(ReservationBusy, state)
        Idle if entry.revision != revision -> #(ReservationStale, state)
        Idle ->
          case entry.tokens.refresh_token {
            None -> #(ReservationNoRefreshToken, state)
            Some(refresh_token) -> {
              let dispatch_id = state.next_dispatch
              let entry =
                Entry(..entry, refresh: Outstanding(dispatch_id, command_id))
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
    Ok(Entry(refresh: Outstanding(id, command_id), ..) as entry)
      if id == dispatch_id
    -> {
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
        Ok(Entry(refresh: Outstanding(id, _), ..) as entry)
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
) -> Result(Receipt, CallError) {
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
  call.call(store.subject, store.timeout, ReserveMsg(
    reference,
    provider,
    revision,
    command_id,
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

pub fn remove(
  store: Store(identity),
  reference: String,
) -> Result(Nil, CallError) {
  call.call(store.subject, store.timeout, RemoveMsg(reference, _))
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
