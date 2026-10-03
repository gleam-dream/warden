//// The record behind `warden.Client`: validated configuration and the
//// names of the processes a started client runs. The names are allocated
//// once, by `warden.new`, so a client value stays valid across supervisor
//// restarts.

import gleam/erlang/process
import gleam/option.{type Option}
import sinal/correlation.{type Correlation}
import warden/internal/custody.{type Custody}
import warden/internal/logins.{type Logins}
import warden/internal/memory_store
import warden/internal/native/client as native
import warden/internal/native/provider
import warden/internal/settings.{type Settings}
import warden/internal/sweeper
import warden/internal/transport

pub type Names {
  Names(
    supervisor: process.Name(Nil),
    provider: process.Name(provider.Message),
    sweeper: process.Name(sweeper.Message),
    /// The in-memory stores, when no durable store is configured.
    memory_custody: Option(process.Name(memory_store.Message)),
    memory_logins: Option(process.Name(memory_store.Message)),
    pool: transport.Pool,
  )
}

pub type Client {
  Client(
    settings: Settings,
    /// `issuer client_id`: binds sessions and recoveries to this client.
    provider: String,
    names: Names,
    backend: native.Client,
    custody: Custody,
    logins: Logins,
    /// Request policy on the client's shared HTTP Gun client.
    http: transport.Policy,
    correlation: Option(Correlation),
  )
}
