import envoy
import exception
import gleam/crypto
import gleam/dynamic/decode
import gleam/erlang/atom
import gleam/erlang/process
import gleam/http/request
import gleam/list
import gleam/option.{None, Some}
import gleam/order
import gleam/time/duration
import gleam/time/timestamp
import gleeunit
import gleeunit/should
import pog
import warden
import warden/config
import warden/store
import warden/testing
import warden_postgres

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn a_record_is_durable_through_a_new_adapter_handle_test() -> Nil {
  use db <- database
  let records = warden_postgres.records(adapter(db))
  testing.check_store(records) |> should.equal(Ok(Nil))
  let record =
    store.Record("first", 1, timestamp.from_unix_seconds(4_000_000_000), <<
      0,
      255,
      1,
    >>)
  store.put(records, record, store.Absent) |> should.equal(Ok(store.Written))
  store.get(warden_postgres.records(adapter(db)), "first")
  |> should.equal(Ok(Some(record)))
}

pub fn expiry_preserves_nanoseconds_and_includes_the_exact_boundary_test() -> Nil {
  use db <- database
  let records = warden_postgres.records(adapter(db))
  let at = fn(nanoseconds) {
    timestamp.from_unix_seconds_and_nanoseconds(2_000_000_000, nanoseconds)
  }
  let record = store.Record("nanoseconds", 1, at(123_456_789), <<0, 255>>)
  store.put(records, record, store.Absent) |> should.equal(Ok(store.Written))
  store.get(records, record.key) |> should.equal(Ok(Some(record)))
  store.delete_expired(records, at(123_456_788)) |> should.equal(Ok(0))
  store.get(records, record.key) |> should.equal(Ok(Some(record)))
  store.delete_expired(records, record.expires_at) |> should.equal(Ok(1))
  store.get(records, record.key) |> should.equal(Ok(None))
}

pub fn lost_write_reply_can_be_reconciled_without_overwriting_test() -> Nil {
  use db <- database
  let records = warden_postgres.records(adapter(db))
  // A synthetic lost acknowledgement after the real PostgreSQL commit.
  // This exercises the store contract, not a driver/network failure.
  let lost_reply =
    store.new(
      get: store.get(records, _),
      put: fn(record, expected) {
        let assert Ok(store.Written) = store.put(records, record, expected)
        Error(store.StoreOutcomeUnknown)
      },
      delete_expired: store.delete_expired(records, _),
    )
  let record =
    store.Record("lost-reply", 1, timestamp.from_unix_seconds(4_000_000_000), <<
      42,
    >>)
  store.put(lost_reply, record, store.Absent)
  |> should.equal(Error(store.StoreOutcomeUnknown))
  store.get(records, record.key) |> should.equal(Ok(Some(record)))
  store.put(records, record, store.Absent)
  |> should.equal(Ok(store.VersionConflict))
}

pub fn login_survives_a_new_client_and_logout_revokes_the_reference_test() -> Nil {
  use db <- database
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  use <- exception.defer(fn() { testing.stop_provider(provider) })
  let assert Ok(key) = config.sealing_key(crypto.strong_random_bytes(32))
  // snips-start: configure-client
  let records = warden_postgres.records(adapter(db))
  let config =
    testing.config(provider, "https://app.test/callback")
    |> config.with_custody_store(records)
    |> config.with_transaction_store(records)
    |> config.with_sealing_key(key)
  // snips-end: configure-client
  let assert Ok(first) = warden.new(config)
  let reference = {
    use <- exception.defer(fn() { warden.stop(first) })
    let assert Ok(Nil) = warden.start(first)
    let assert Ok(redirect) =
      warden.begin_login(first, request.new(), warden.default_login())
    let assert Ok(callback) =
      testing.authorize(provider, redirect, subject: "alice")
    let assert Ok(session) = warden.complete_login(first, callback)
    warden.complete_login(first, callback) |> should.be_error
    warden.session_reference(session)
  }
  let assert Ok(second) = warden.new(config)
  use <- exception.defer(fn() { warden.stop(second) })
  let assert Ok(Nil) = warden.start(second)
  let assert Ok(session) = warden.restore_session(second, reference)
  session
  |> warden.session_identity
  |> warden.subject
  |> should.equal("alice")
  let assert Ok(warden.LoggedOut(..)) =
    warden.logout(second, session, warden.default_logout())
  warden.restore_session(second, reference)
  |> should.equal(Error(warden.SessionNotFound))
}

fn database(check: fn(process.Name(pog.Message)) -> Nil) -> Nil {
  let assert Ok(url) = envoy.get("WARDEN_POSTGRES_TEST_URL")
  let name = process.new_name("warden_postgres_test")
  let assert Ok(config) = pog.url_config(name, url)
  let assert Ok(pool) = pog.start(pog.pool_size(config, 8))
  use <- exception.defer(fn() {
    let monitor = process.monitor(pool.pid)
    process.unlink(pool.pid)
    process.send_abnormal_exit(pool.pid, atom.create("shutdown"))
    let assert Ok(Nil) =
      process.new_selector()
      |> process.select_specific_monitor(monitor, fn(_) { Nil })
      |> process.selector_receive(5000)
    Nil
  })
  let assert Ok(Nil) = warden_postgres.initialize(adapter(name))
  let assert Ok(_) =
    pog.query("TRUNCATE warden.records")
    |> pog.execute(pool.data)
  check(name)
}

fn adapter(name: process.Name(pog.Message)) -> warden_postgres.Adapter {
  let assert Ok(adapter) = warden_postgres.new(warden_postgres.config(name))
  adapter
}

pub fn isolated_quoted_schema_survives_reinitialization_test() -> Nil {
  use name <- database
  // snips-start: configure-adapter
  let config = warden_postgres.config(name)
  let assert Ok(isolated) =
    warden_postgres.new(
      config
      |> warden_postgres.with_schema("Other\"Warden")
      |> warden_postgres.with_timeouts(statement_ms: 2000, lock_ms: 250),
    )
  let assert Ok(Nil) = warden_postgres.initialize(isolated)
  let records = warden_postgres.records(isolated)
  // snips-end: configure-adapter
  let record =
    store.Record("isolated", -1, timestamp.from_unix_seconds(0), <<255, 0>>)
  store.put(records, record, store.Absent) |> should.equal(Ok(store.Written))
  warden_postgres.initialize(isolated) |> should.equal(Ok(Nil))
  store.get(records, record.key) |> should.equal(Ok(Some(record)))
  store.get(warden_postgres.records(adapter(name)), record.key)
  |> should.equal(Ok(None))
  // Expiry never turns insert into an unconditional overwrite.
  store.put(records, store.Record(..record, version: 2), store.Absent)
  |> should.equal(Ok(store.VersionConflict))
}

pub fn unknown_format_is_refused_by_both_initialization_and_existing_handle_test() -> Nil {
  use name <- database
  let config = warden_postgres.config(name)
  let assert Ok(isolated) =
    warden_postgres.new(warden_postgres.with_schema(config, "future_warden"))
  let assert Ok(Nil) = warden_postgres.initialize(isolated)
  let records = warden_postgres.records(isolated)
  let record = store.Record("future", 1, timestamp.from_unix_seconds(0), <<42>>)
  store.put(records, record, store.Absent) |> should.equal(Ok(store.Written))
  let db = pog.named_connection(name)
  let assert Ok(_) =
    pog.query("UPDATE future_warden.format SET version = 99") |> pog.execute(db)
  warden_postgres.initialize(isolated)
  |> should.equal(Error(warden_postgres.UnsupportedVersion(99)))
  store.get(records, record.key) |> should.equal(Error(store.StoreUnavailable))
  store.put(records, store.Record(..record, version: 2), store.AtVersion(1))
  |> should.equal(Error(store.StoreUnavailable))
  store.delete_expired(records, record.expires_at)
  |> should.equal(Error(store.StoreUnavailable))
  let assert Ok(_) =
    pog.query("UPDATE future_warden.format SET version = 1") |> pog.execute(db)
  store.get(records, record.key) |> should.equal(Ok(Some(record)))
}

pub fn invalid_settings_are_rejected_without_a_running_pool_test() -> Nil {
  let config = warden_postgres.config(process.new_name("absent_pool"))
  warden_postgres.new(warden_postgres.with_schema(config, ""))
  |> should.equal(Error(warden_postgres.InvalidSchema))
  warden_postgres.new(warden_postgres.with_schema(config, "pg_catalog"))
  |> should.equal(Error(warden_postgres.InvalidSchema))
  warden_postgres.new(warden_postgres.with_timeouts(
    config,
    statement_ms: 1000,
    lock_ms: 0,
  ))
  |> should.equal(Error(warden_postgres.InvalidLimits))
  warden_postgres.new(warden_postgres.with_timeouts(
    config,
    statement_ms: 1000,
    lock_ms: 1001,
  ))
  |> should.equal(Error(warden_postgres.InvalidLimits))
  warden_postgres.new(warden_postgres.with_timeouts(
    config,
    statement_ms: 0,
    lock_ms: 1,
  ))
  |> should.equal(Error(warden_postgres.InvalidLimits))
  warden_postgres.new(warden_postgres.with_timeouts(
    config,
    statement_ms: 60_001,
    lock_ms: 1,
  ))
  |> should.equal(Error(warden_postgres.InvalidLimits))
  warden_postgres.new(warden_postgres.with_timeouts(
    config,
    statement_ms: 60_000,
    lock_ms: 60_000,
  ))
  |> should.be_ok
  Nil
}

pub fn unavailable_pool_never_falls_back_or_panics_test() -> Nil {
  let records =
    warden_postgres.records(adapter(process.new_name("missing_pool")))
  store.get(records, "missing") |> should.equal(Error(store.StoreUnavailable))
  store.put(
    records,
    store.Record("missing", 1, timestamp.from_unix_seconds(0), <<>>),
    store.Absent,
  )
  |> should.equal(Error(store.StoreOutcomeUnknown))
  store.delete_expired(records, timestamp.from_unix_seconds(0))
  |> should.equal(Error(store.StoreOutcomeUnknown))
}

pub fn locked_record_times_out_without_overwriting_and_pool_stays_usable_test() -> Nil {
  use name <- database
  let config = warden_postgres.config(name)
  let assert Ok(limited) =
    warden_postgres.new(warden_postgres.with_timeouts(
      config,
      statement_ms: 300,
      lock_ms: 50,
    ))
  let records = warden_postgres.records(limited)
  let record = store.Record("locked", 1, timestamp.from_unix_seconds(0), <<42>>)
  store.put(records, record, store.Absent) |> should.equal(Ok(store.Written))
  let locked = process.new_subject()
  let finished = process.new_subject()
  let _ =
    process.spawn(fn() {
      let release = process.new_subject()
      let assert Ok(Nil) =
        pog.transaction(pog.named_connection(name), fn(db) {
          let assert Ok(_) =
            pog.query(
              "SELECT key FROM warden.records WHERE key = 'locked' FOR UPDATE",
            )
            |> pog.execute(db)
          process.send(locked, release)
          let assert Ok(Nil) = process.receive(release, 5000)
          Ok(Nil)
        })
      process.send(finished, Nil)
    })
  let assert Ok(release) = process.receive(locked, 5000)
  let result =
    store.put(records, store.Record(..record, version: 2), store.AtVersion(1))
  process.send(release, Nil)
  let assert Ok(Nil) = process.receive(finished, 5000)
  result |> should.equal(Error(store.StoreOutcomeUnknown))
  store.get(records, record.key) |> should.equal(Ok(Some(record)))
  store.put(records, store.Record(..record, version: 2), store.AtVersion(1))
  |> should.equal(Ok(store.Written))
}

pub fn two_clients_share_one_rotating_refresh_through_postgres_test() -> Nil {
  use name <- database
  let assert Ok(provider) =
    testing.start_provider(
      testing.provider_options()
      |> testing.with_refresh_delay(duration.milliseconds(200)),
    )
  use <- exception.defer(fn() { testing.stop_provider(provider) })
  let assert Ok(key) = config.sealing_key(crypto.strong_random_bytes(32))
  let records = warden_postgres.records(adapter(name))
  let config =
    testing.config(provider, "https://app.test/callback")
    |> config.with_scopes(["email", "profile", "offline_access"])
    |> config.with_custody_store(records)
    |> config.with_transaction_store(records)
    |> config.with_sealing_key(key)
  let assert Ok(first) = warden.new(config)
  let assert Ok(second) = warden.new(config)
  use <- exception.defer(fn() { warden.stop(first) })
  use <- exception.defer(fn() { warden.stop(second) })
  let assert Ok(Nil) = warden.start(first)
  let assert Ok(Nil) = warden.start(second)
  let assert Ok(redirect) =
    warden.begin_login(first, request.new(), warden.default_login())
  let assert Ok(callback) =
    testing.authorize(provider, redirect, subject: "alice")
  let assert Ok(session) = warden.complete_login(first, callback)
  let assert Ok(restored) =
    warden.restore_session(second, warden.session_reference(session))
  let answers = process.new_subject()
  let requests = [
    #(first, session),
    #(second, restored),
    #(first, session),
    #(second, restored),
  ]
  list.each(requests, fn(pair) {
    let _ =
      process.spawn(fn() {
        process.send(answers, warden.refresh(pair.0, pair.1))
      })
    Nil
  })
  let tokens =
    list.map(requests, fn(_) {
      let assert Ok(Ok(access)) = process.receive(answers, 5000)
      warden.access_token_value(access.token)
    })
  tokens |> list.unique |> list.length |> should.equal(1)
  testing.requests(provider).refresh_grants |> should.equal(1)
  testing.requests(provider).rejected_refresh_grants |> should.equal(0)
}

// Observe PostgreSQL's lock graph, then release the holder across the deadline.
type LockedChange {
  KeepRecord
  ChangeVersion
  DeleteRecord
  ReleaseBeforeDeadline
}

pub fn guarded_write_expiring_during_row_lock_is_refused_test() -> Nil {
  guarded_after_lock(KeepRecord)
}

pub fn changed_version_precedes_elapsed_deadline_after_lock_test() -> Nil {
  guarded_after_lock(ChangeVersion)
}

pub fn missing_row_precedes_elapsed_deadline_after_lock_test() -> Nil {
  guarded_after_lock(DeleteRecord)
}

pub fn guarded_write_released_before_deadline_succeeds_test() -> Nil {
  guarded_after_lock(ReleaseBeforeDeadline)
}

fn guarded_after_lock(change: LockedChange) -> Nil {
  use name <- database
  let config = warden_postgres.config(name)
  let assert Ok(adapter) =
    warden_postgres.new(warden_postgres.with_timeouts(
      config,
      statement_ms: 6000,
      lock_ms: 5000,
    ))
  let records = warden_postgres.records(adapter)
  let original =
    store.Record(
      "deadline-lock",
      1,
      timestamp.from_unix_seconds(4_000_000_000),
      <<1>>,
    )
  store.put(records, original, store.Absent) |> should.equal(Ok(store.Written))
  let replacement = store.Record(..original, version: 2, sealed: <<2>>)
  let locked = process.new_subject()
  let finished = process.new_subject()
  let _ =
    process.spawn(fn() {
      let release = process.new_subject()
      let assert Ok(Nil) =
        pog.transaction(pog.named_connection(name), fn(db) {
          let assert Ok(row) =
            pog.query(
              "SELECT pg_backend_pid() FROM warden.records WHERE key = $1 FOR UPDATE",
            )
            |> pog.parameter(pog.text(original.key))
            |> pog.returning(decode.field(0, decode.int, decode.success))
            |> pog.execute(db)
          let assert [pid] = row.rows
          process.send(locked, #(pid, release))
          let assert Ok(Nil) = process.receive(release, 7000)
          let mutation = case change {
            KeepRecord | ReleaseBeforeDeadline -> None
            ChangeVersion ->
              Some("UPDATE warden.records SET version = 3 WHERE key = $1")
            DeleteRecord -> Some("DELETE FROM warden.records WHERE key = $1")
          }
          case mutation {
            None -> Nil
            Some(sql) -> {
              let assert Ok(_) =
                pog.query(sql)
                |> pog.parameter(pog.text(original.key))
                |> pog.execute(db)
              Nil
            }
          }
          Ok(Nil)
        })
      process.send(finished, Nil)
    })
  let assert Ok(#(blocker, release)) = process.receive(locked, 5000)
  use <- exception.defer(fn() { process.send(release, Nil) })
  let seconds_ahead = case change {
    ReleaseBeforeDeadline -> 60
    KeepRecord | ChangeVersion | DeleteRecord -> 2
  }
  let assert Ok(time) =
    pog.query(
      "SELECT floor(EXTRACT(EPOCH FROM clock_timestamp()))::bigint + $1",
    )
    |> pog.parameter(pog.int(seconds_ahead))
    |> pog.returning(decode.field(0, decode.int, decode.success))
    |> pog.execute(pog.named_connection(name))
  let assert [deadline_seconds] = time.rows
  let completed = process.new_subject()
  let _ =
    process.spawn(fn() {
      process.send(
        completed,
        store.put(
          records,
          replacement,
          store.AtVersionBefore(
            1,
            timestamp.from_unix_seconds(deadline_seconds),
          ),
        ),
      )
    })
  await_database(
    fn() {
      let assert Ok(found) =
        pog.query(
          "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND $1 = ANY(pg_blocking_pids(pid)))",
        )
        |> pog.parameter(pog.int(blocker))
        |> pog.returning(decode.field(0, decode.bool, decode.success))
        |> pog.execute(pog.named_connection(name))
      found.rows == [True]
    },
    400,
  )
  let assert Ok(while_blocked) =
    pog.query("SELECT EXTRACT(EPOCH FROM clock_timestamp()) < $1")
    |> pog.parameter(pog.int(deadline_seconds))
    |> pog.returning(decode.field(0, decode.bool, decode.success))
    |> pog.execute(pog.named_connection(name))
  while_blocked.rows |> should.equal([True])
  case change {
    ReleaseBeforeDeadline -> Nil
    KeepRecord | ChangeVersion | DeleteRecord ->
      await_database(
        fn() {
          let assert Ok(time) =
            pog.query("SELECT EXTRACT(EPOCH FROM clock_timestamp()) >= $1")
            |> pog.parameter(pog.int(deadline_seconds))
            |> pog.returning(decode.field(0, decode.bool, decode.success))
            |> pog.execute(pog.named_connection(name))
          time.rows == [True]
        },
        400,
      )
  }
  process.send(release, Nil)
  let assert Ok(Nil) = process.receive(finished, 5000)
  let assert Ok(outcome) = process.receive(completed, 5000)
  let #(expected, stored) = case change {
    KeepRecord -> #(store.DeadlineElapsed, Some(original))
    ChangeVersion -> #(
      store.VersionConflict,
      Some(store.Record(..original, version: 3)),
    )
    DeleteRecord -> #(store.VersionConflict, None)
    ReleaseBeforeDeadline -> #(store.Written, Some(replacement))
  }
  outcome |> should.equal(Ok(expected))
  store.get(records, original.key) |> should.equal(Ok(stored))
}

fn await_database(check: fn() -> Bool, attempts: Int) -> Nil {
  case check() {
    True -> Nil
    False -> {
      should.be_true(attempts > 0)
      process.sleep(10)
      await_database(check, attempts - 1)
    }
  }
}

type ConsumptionDelay {
  BeforeConsumption
  AfterConsumption
  LostConsumptionReply
}

pub fn postgres_delayed_consumption_prevents_expired_login_exchange_test() -> Nil {
  delayed_consumption(BeforeConsumption)
}

pub fn postgres_timely_consumption_allows_late_acknowledgement_test() -> Nil {
  delayed_consumption(AfterConsumption)
}

pub fn postgres_unknown_consumption_never_authorizes_exchange_test() -> Nil {
  delayed_consumption(LostConsumptionReply)
}

fn delayed_consumption(delay: ConsumptionDelay) -> Nil {
  use name <- database
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  use <- exception.defer(fn() { testing.stop_provider(provider) })
  let records = warden_postgres.records(adapter(name))
  let guarded =
    store.new(
      get: store.get(records, _),
      put: fn(record, condition) {
        case condition {
          store.Absent | store.AtVersion(_) ->
            store.put(records, record, condition)
          store.AtVersionBefore(_, deadline) -> {
            timestamp.compare(timestamp.system_time(), deadline)
            |> should.equal(order.Lt)
            case delay {
              BeforeConsumption -> process.sleep(2500)
              AfterConsumption | LostConsumptionReply -> Nil
            }
            let outcome = store.put(records, record, condition)
            case delay {
              BeforeConsumption -> outcome
              AfterConsumption -> {
                process.sleep(2500)
                outcome
              }
              LostConsumptionReply -> {
                outcome |> should.equal(Ok(store.Written))
                Error(store.StoreOutcomeUnknown)
              }
            }
          }
        }
      },
      delete_expired: store.delete_expired(records, _),
    )
  let assert Ok(key) = config.sealing_key(crypto.strong_random_bytes(32))
  let assert Ok(client) =
    testing.config(provider, "https://app.test/callback")
    |> config.with_transaction_store(guarded)
    |> config.with_sealing_key(key)
    |> config.with_login_lifetime(duration.seconds(2))
    |> config.with_store_timeout(duration.seconds(10))
    |> warden.new
  use <- exception.defer(fn() { warden.stop(client) })
  let assert Ok(Nil) = warden.start(client)
  let assert Ok(redirect) =
    warden.begin_login(client, request.new(), warden.default_login())
  let assert Ok(callback) =
    testing.authorize(provider, redirect, subject: "alice")
  let completed = warden.complete_login(client, callback)
  case delay {
    BeforeConsumption -> {
      completed |> should.equal(Error(warden.LoginExpired))
      testing.requests(provider).code_grants |> should.equal(0)
    }
    AfterConsumption -> {
      completed |> should.be_ok
      testing.requests(provider).code_grants |> should.equal(1)
      warden.complete_login(client, callback)
      |> should.equal(Error(warden.LoginReplayed))
    }
    LostConsumptionReply -> {
      completed |> should.equal(Error(warden.TransactionStoreUnavailable))
      testing.requests(provider).code_grants |> should.equal(0)
      warden.complete_login(client, callback)
      |> should.equal(Error(warden.LoginReplayed))
    }
  }
}
