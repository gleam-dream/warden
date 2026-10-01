//// Typed Gleam view of the oidcc boundary (`warden_oidcc.erl`).
////
//// Every foreign result is decoded totally: an unexpected shape becomes
//// `Unmapped`, never a crash and never success. Failures carry closed
//// classifications only.

import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/erlang/process.{type Pid}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import warden/config.{type Config}

/// Transport adapter configuration term (opaque Erlang value).
pub type Adapter

/// Client description term (opaque Erlang value).
pub type ClientTerm

pub type Backend {
  Backend(worker: WorkerName, adapter: Adapter, client: ClientTerm)
}

/// The atom under which the oidcc provider worker is registered.
pub type WorkerName

pub type Metadata {
  Metadata(
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: Option(String),
    userinfo_endpoint: Option(String),
    introspection_endpoint: Option(String),
    end_session_endpoint: Option(String),
    code_challenge_methods: List(String),
    grant_types: List(String),
    response_modes: List(String),
    auth_methods: List(String),
    auth_signing_algorithms: List(String),
    id_token_algorithms: List(String),
    issuer_parameter_supported: Bool,
    requires_par: Bool,
    requires_signed_request_object: Bool,
  )
}

pub type Failure {
  /// The provider worker has no loaded metadata or keys. Nothing was sent.
  NotReady
  /// Transport failure. `sent` is False only when no byte reached the peer.
  Transport(sent: Bool, class: String)
  /// The endpoint answered with a non-success status. `error` is the closed
  /// OAuth error code (`invalid_grant`, ...), `other`, or `none`.
  Endpoint(status: Int, error: String)
  /// A success status with an unusable body (content type, JSON, fields).
  Malformed
  /// ID-token or JWT validation failed; `reason` is a closed code.
  IdTokenInvalid(reason: String, claim: Option(String))
  /// A local policy refusal before any request (unsupported method, PKCE,
  /// grant, required PAR, missing endpoint, ...).
  Policy(reason: String)
  UserinfoSubjectMismatch
  Unmapped
}

pub type IdToken {
  IdToken(token: String, claims: Dynamic)
}

pub type TokenResponse {
  TokenResponse(
    access_token: Option(String),
    token_type: String,
    expires_in: Option(Int),
    refresh_token: Option(String),
    id_token: Option(IdToken),
    id_token_malformed: Bool,
    scopes: List(String),
  )
}

pub type Introspected {
  Inactive
  Active(
    client_id: Option(String),
    subject: Option(String),
    username: Option(String),
    scopes: List(String),
    expires_at: Option(Int),
    issued_at: Option(Int),
    token_type: Option(String),
    issuer: Option(String),
    extra: Dynamic,
  )
}

// ---------------------------------------------------------------------------
// Construction

pub fn adapter(config: Config) -> Adapter {
  make_adapter(
    config.trust_anchors(config),
    config.destinations(config),
    config.allowed_hosts(config),
    config.request_timeout_ms(config),
    config.max_response_bytes(config),
  )
}

@external(erlang, "warden_oidcc", "adapter")
fn make_adapter(
  trust: config.TrustAnchors,
  destinations: config.DestinationPolicy,
  allowed_hosts: Option(List(String)),
  timeout: Int,
  max_body: Int,
) -> Adapter

pub fn new(
  config: Config,
  worker: WorkerName,
  adapter: Adapter,
  assume_s256: Bool,
) -> Backend {
  let client =
    make_client(
      worker,
      config.client_id(config),
      config.authentication_method(config),
      config.trusted_credential(config),
      config.signing_algorithms(config),
      config.assertion_algorithms(config),
      assume_s256,
    )
  Backend(worker:, adapter:, client:)
}

@external(erlang, "warden_oidcc", "client")
fn make_client(
  worker: WorkerName,
  client_id: String,
  auth_method: String,
  credential: Option(String),
  id_token_algorithms: List(String),
  assertion_algorithms: List(String),
  assume_s256: Bool,
) -> ClientTerm

@external(erlang, "warden_ffi", "identity")
pub fn worker_name(name: process.Name(a)) -> WorkerName

// ---------------------------------------------------------------------------
// Provider

/// Start the OTP applications the boundary needs; False when they cannot
/// start.
@external(erlang, "warden_oidcc", "ensure_started")
pub fn ensure_started() -> Bool

pub fn load_metadata(
  issuer: String,
  adapter: Adapter,
) -> Result(Metadata, Failure) {
  ffi_load_metadata(issuer, adapter) |> decode_result(metadata_decoder())
}

pub fn start_worker(
  name: WorkerName,
  issuer: String,
  adapter: Adapter,
) -> Result(Pid, Nil) {
  ffi_start_worker(name, issuer, adapter)
  |> result.replace_error(Nil)
}

pub fn ready(name: WorkerName) -> Bool {
  ffi_ready(name)
}

pub fn metadata(backend: Backend) -> Result(Metadata, Failure) {
  ffi_metadata(backend.worker) |> decode_result(metadata_decoder())
}

@external(erlang, "warden_oidcc", "load_metadata")
fn ffi_load_metadata(
  issuer: String,
  adapter: Adapter,
) -> Result(Dynamic, Dynamic)

@external(erlang, "warden_oidcc", "start_worker")
fn ffi_start_worker(
  name: WorkerName,
  issuer: String,
  adapter: Adapter,
) -> Result(Pid, Dynamic)

@external(erlang, "warden_oidcc", "ready")
fn ffi_ready(name: WorkerName) -> Bool

@external(erlang, "warden_oidcc", "metadata")
fn ffi_metadata(name: WorkerName) -> Result(Dynamic, Dynamic)

// ---------------------------------------------------------------------------
// Operations

pub type AuthorizationParams {
  AuthorizationParams(
    redirect_uri: String,
    state: String,
    nonce: String,
    verifier: String,
    scopes: List(String),
    response_mode: String,
    extension: List(#(String, String)),
  )
}

pub fn authorization_url(
  backend: Backend,
  params: AuthorizationParams,
) -> Result(String, Failure) {
  ffi_authorization_url(
    backend.client,
    params_map([
      #("adapter", to_dynamic(backend.adapter)),
      #("redirect_uri", to_dynamic(params.redirect_uri)),
      #("state", to_dynamic(params.state)),
      #("nonce", to_dynamic(params.nonce)),
      #("verifier", to_dynamic(params.verifier)),
      #("scopes", to_dynamic(params.scopes)),
      #("response_mode", to_dynamic(params.response_mode)),
      #("extension", to_dynamic(params.extension)),
    ]),
  )
  |> decode_result(decode.string)
}

pub fn exchange_code(
  backend: Backend,
  code code: String,
  redirect_uri redirect_uri: String,
  nonce nonce: String,
  verifier verifier: String,
) -> Result(TokenResponse, Failure) {
  ffi_exchange_code(
    backend.client,
    params_map([
      #("adapter", to_dynamic(backend.adapter)),
      #("code", to_dynamic(code)),
      #("redirect_uri", to_dynamic(redirect_uri)),
      #("nonce", to_dynamic(nonce)),
      #("verifier", to_dynamic(verifier)),
    ]),
  )
  |> decode_result(token_decoder())
}

pub fn refresh(
  backend: Backend,
  refresh_token refresh_token: String,
  expected_subject expected_subject: String,
) -> Result(TokenResponse, Failure) {
  ffi_refresh(
    backend.client,
    params_map([
      #("adapter", to_dynamic(backend.adapter)),
      #("refresh_token", to_dynamic(refresh_token)),
      #("expected_subject", to_dynamic(expected_subject)),
    ]),
  )
  |> decode_result(token_decoder())
}

pub fn userinfo(
  backend: Backend,
  access_token access_token: String,
  expected_subject expected_subject: String,
) -> Result(Dynamic, Failure) {
  ffi_userinfo(
    backend.client,
    params_map([
      #("adapter", to_dynamic(backend.adapter)),
      #("access_token", to_dynamic(access_token)),
      #("expected_subject", to_dynamic(expected_subject)),
    ]),
  )
  |> decode_result(decode.dynamic)
}

pub fn introspect(
  backend: Backend,
  token: String,
) -> Result(Introspected, Failure) {
  ffi_introspect(
    backend.client,
    params_map([
      #("adapter", to_dynamic(backend.adapter)),
      #("token", to_dynamic(token)),
    ]),
  )
  |> decode_result(introspection_decoder())
}

pub fn client_credentials(
  backend: Backend,
  scopes: List(String),
) -> Result(TokenResponse, Failure) {
  ffi_client_credentials(
    backend.client,
    params_map([
      #("adapter", to_dynamic(backend.adapter)),
      #("scopes", to_dynamic(scopes)),
    ]),
  )
  |> decode_result(token_decoder())
}

pub fn logout_url(
  backend: Backend,
  id_token_hint id_token_hint: Option(String),
  post_logout_redirect_uri post_logout_redirect_uri: Option(String),
  state state: Option(String),
) -> Result(String, Failure) {
  ffi_logout_url(
    backend.client,
    params_map([
      #("id_token_hint", to_dynamic(id_token_hint)),
      #("post_logout_redirect_uri", to_dynamic(post_logout_redirect_uri)),
      #("state", to_dynamic(state)),
    ]),
  )
  |> decode_result(decode.string)
}

type Params

@external(erlang, "warden_oidcc", "authorization_url")
fn ffi_authorization_url(
  client: ClientTerm,
  params: Params,
) -> Result(Dynamic, Dynamic)

@external(erlang, "warden_oidcc", "exchange_code")
fn ffi_exchange_code(
  client: ClientTerm,
  params: Params,
) -> Result(Dynamic, Dynamic)

@external(erlang, "warden_oidcc", "refresh")
fn ffi_refresh(client: ClientTerm, params: Params) -> Result(Dynamic, Dynamic)

@external(erlang, "warden_oidcc", "userinfo")
fn ffi_userinfo(client: ClientTerm, params: Params) -> Result(Dynamic, Dynamic)

@external(erlang, "warden_oidcc", "introspect")
fn ffi_introspect(
  client: ClientTerm,
  params: Params,
) -> Result(Dynamic, Dynamic)

@external(erlang, "warden_oidcc", "client_credentials")
fn ffi_client_credentials(
  client: ClientTerm,
  params: Params,
) -> Result(Dynamic, Dynamic)

@external(erlang, "warden_oidcc", "logout_url")
fn ffi_logout_url(
  client: ClientTerm,
  params: Params,
) -> Result(Dynamic, Dynamic)

/// Parameter maps use atom keys on the Erlang side.
@external(erlang, "warden_oidcc", "params")
fn params_map(entries: List(#(String, Dynamic))) -> Params

@external(erlang, "warden_ffi", "identity")
fn to_dynamic(value: a) -> Dynamic

// ---------------------------------------------------------------------------
// Decoding

fn decode_result(
  result: Result(Dynamic, Dynamic),
  decoder: decode.Decoder(a),
) -> Result(a, Failure) {
  case result {
    Ok(value) ->
      decode.run(value, decoder)
      |> result.replace_error(Unmapped)
    Error(error) ->
      Error(
        decode.run(error, failure_decoder())
        |> result.unwrap(Unmapped),
      )
  }
}

fn failure_decoder() -> decode.Decoder(Failure) {
  use kind <- decode.field("kind", decode.string)
  use detail <- decode.optional_field("detail", "", decode.string)
  case kind {
    "not_ready" -> decode.success(NotReady)
    "transport" -> {
      use stage <- decode.field("stage", decode.string)
      decode.success(Transport(sent: stage != "not_sent", class: detail))
    }
    "endpoint" -> {
      use status <- decode.field("status", decode.int)
      decode.success(Endpoint(status:, error: detail))
    }
    "response" -> decode.success(Malformed)
    "id_token" -> {
      use claim <- decode.optional_field(
        "claim",
        None,
        decode.map(decode.string, Some),
      )
      decode.success(IdTokenInvalid(reason: detail, claim:))
    }
    "policy" -> decode.success(Policy(detail))
    "userinfo" -> decode.success(UserinfoSubjectMismatch)
    _ -> decode.success(Unmapped)
  }
}

fn metadata_decoder() -> decode.Decoder(Metadata) {
  let nullable = decode.optional(decode.string)
  use issuer <- decode.field("issuer", decode.string)
  use authorization_endpoint <- decode.field(
    "authorization_endpoint",
    decode.string,
  )
  use token_endpoint <- decode.field("token_endpoint", nullable)
  use userinfo_endpoint <- decode.field("userinfo_endpoint", nullable)
  use introspection_endpoint <- decode.field("introspection_endpoint", nullable)
  use end_session_endpoint <- decode.field("end_session_endpoint", nullable)
  use code_challenge_methods <- decode.field(
    "code_challenge_methods_supported",
    decode.list(decode.string),
  )
  use grant_types <- decode.field(
    "grant_types_supported",
    decode.list(decode.string),
  )
  use response_modes <- decode.field(
    "response_modes_supported",
    decode.list(decode.string),
  )
  use auth_methods <- decode.field(
    "token_endpoint_auth_methods_supported",
    decode.list(decode.string),
  )
  use auth_signing_algorithms <- decode.field(
    "token_endpoint_auth_signing_alg_values_supported",
    decode.list(decode.string),
  )
  use id_token_algorithms <- decode.field(
    "id_token_signing_alg_values_supported",
    decode.list(decode.string),
  )
  use issuer_parameter_supported <- decode.field(
    "authorization_response_iss_parameter_supported",
    decode.bool,
  )
  use requires_par <- decode.field(
    "require_pushed_authorization_requests",
    decode.bool,
  )
  use requires_signed_request_object <- decode.field(
    "require_signed_request_object",
    decode.bool,
  )
  decode.success(Metadata(
    issuer:,
    authorization_endpoint:,
    token_endpoint:,
    userinfo_endpoint:,
    introspection_endpoint:,
    end_session_endpoint:,
    code_challenge_methods:,
    grant_types:,
    response_modes:,
    auth_methods:,
    auth_signing_algorithms:,
    id_token_algorithms:,
    issuer_parameter_supported:,
    requires_par:,
    requires_signed_request_object:,
  ))
}

fn token_decoder() -> decode.Decoder(TokenResponse) {
  let opt_string = decode.optional(decode.string)
  use access_token <- decode.optional_field("access_token", None, opt_string)
  use token_type <- decode.optional_field("token_type", "Bearer", decode.string)
  use expires_in <- decode.optional_field(
    "expires_in",
    None,
    decode.optional(decode.int),
  )
  use refresh_token <- decode.optional_field("refresh_token", None, opt_string)
  use id_token_text <- decode.optional_field("id_token", None, opt_string)
  use claims <- decode.optional_field(
    "claims",
    None,
    decode.map(decode.dynamic, Some),
  )
  use id_token_malformed <- decode.optional_field(
    "id_token_malformed",
    False,
    decode.bool,
  )
  use scopes <- decode.optional_field("scope", [], decode.list(decode.string))
  let id_token = case id_token_text, claims {
    Some(token), Some(claims) -> Some(IdToken(token:, claims:))
    _, _ -> None
  }
  decode.success(TokenResponse(
    access_token:,
    token_type:,
    expires_in:,
    refresh_token:,
    id_token:,
    id_token_malformed:,
    scopes:,
  ))
}

fn introspection_decoder() -> decode.Decoder(Introspected) {
  use active <- decode.field("active", decode.bool)
  case active {
    False -> decode.success(Inactive)
    True -> {
      let opt_string = decode.optional(decode.string)
      let opt_int = decode.optional(decode.int)
      use client_id <- decode.field("client_id", opt_string)
      use subject <- decode.field("sub", opt_string)
      use username <- decode.field("username", opt_string)
      use scopes <- decode.field("scope", decode.list(decode.string))
      use expires_at <- decode.field("exp", opt_int)
      use issued_at <- decode.field("iat", opt_int)
      use token_type <- decode.field("token_type", opt_string)
      use issuer <- decode.field("iss", opt_string)
      use extra <- decode.field("extra", decode.dynamic)
      decode.success(Active(
        client_id:,
        subject:,
        username:,
        scopes:,
        expires_at:,
        issued_at:,
        token_type:,
        issuer:,
        extra:,
      ))
    }
  }
}

/// Claim helpers over a JSON-shaped claims term.
pub fn string_claim(claims: Dynamic, name: String) -> Option(String) {
  decode.run(claims, decode.at([name], decode.string))
  |> option.from_result
}

pub fn int_claim(claims: Dynamic, name: String) -> Option(Int) {
  decode.run(claims, decode.at([name], decode.int))
  |> option.from_result
}

pub fn audiences(claims: Dynamic) -> List(String) {
  let single = decode.at(["aud"], decode.map(decode.string, list.wrap))
  let many = decode.at(["aud"], decode.list(decode.string))
  decode.run(claims, decode.one_of(single, [many]))
  |> result.unwrap([])
}
