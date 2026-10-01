//// The backend seam (design §5). Warden's orchestration calls these
//// operations; the configured backend performs them. The native backend
//// (gose) and the oidcc backend return the same `protocol` types, so binding
//// checks, custody and refresh state stay in one owner for both.

import gleam/dynamic.{type Dynamic}
import gleam/option.{type Option}
import warden/internal/native/client as native
import warden/internal/oidcc_backend as oidcc
import warden/internal/protocol.{
  type AuthorizationParams, type Failure, type Introspected, type Metadata,
  type TokenResponse,
}

pub type Backend {
  Native(native.Client)
  Oidcc(oidcc.Backend)
}

pub fn metadata(backend: Backend) -> Result(Metadata, Failure) {
  case backend {
    Native(client) -> native.metadata(client)
    Oidcc(b) -> oidcc.metadata(b)
  }
}

pub fn authorization_url(
  backend: Backend,
  params: AuthorizationParams,
) -> Result(String, Failure) {
  case backend {
    Native(client) -> native.authorization_url(client, params)
    Oidcc(b) -> oidcc.authorization_url(b, params)
  }
}

pub fn exchange_code(
  backend: Backend,
  code code: String,
  redirect_uri redirect_uri: String,
  nonce nonce: String,
  verifier verifier: String,
) -> Result(TokenResponse, Failure) {
  case backend {
    Native(client) ->
      native.exchange_code(client, code:, redirect_uri:, nonce:, verifier:)
    Oidcc(b) -> oidcc.exchange_code(b, code:, redirect_uri:, nonce:, verifier:)
  }
}

pub fn refresh(
  backend: Backend,
  refresh_token refresh_token: String,
  expected_subject expected_subject: String,
) -> Result(TokenResponse, Failure) {
  case backend {
    Native(client) -> native.refresh(client, refresh_token:, expected_subject:)
    Oidcc(b) -> oidcc.refresh(b, refresh_token:, expected_subject:)
  }
}

pub fn userinfo(
  backend: Backend,
  access_token access_token: String,
  expected_subject expected_subject: String,
) -> Result(Dynamic, Failure) {
  case backend {
    Native(client) -> native.userinfo(client, access_token:, expected_subject:)
    Oidcc(b) -> oidcc.userinfo(b, access_token:, expected_subject:)
  }
}

pub fn introspect(
  backend: Backend,
  token: String,
) -> Result(Introspected, Failure) {
  case backend {
    Native(client) -> native.introspect(client, token)
    Oidcc(b) -> oidcc.introspect(b, token)
  }
}

pub fn client_credentials(
  backend: Backend,
  scopes: List(String),
) -> Result(TokenResponse, Failure) {
  case backend {
    Native(client) -> native.client_credentials(client, scopes)
    Oidcc(b) -> oidcc.client_credentials(b, scopes)
  }
}

pub fn logout_url(
  backend: Backend,
  id_token_hint id_token_hint: Option(String),
  post_logout_redirect_uri post_logout_redirect_uri: Option(String),
  state state: Option(String),
) -> Result(String, Failure) {
  case backend {
    Native(client) ->
      native.logout_url(
        client,
        id_token_hint:,
        post_logout_redirect_uri:,
        state:,
      )
    Oidcc(b) ->
      oidcc.logout_url(b, id_token_hint:, post_logout_redirect_uri:, state:)
  }
}
