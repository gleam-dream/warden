//// Types shared by Warden's backends: provider metadata, token responses,
//// introspection results and the closed failure classification, plus claim
//// helpers over JSON-shaped claim terms.

import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/list
import gleam/option.{type Option}
import gleam/result

pub type Metadata {
  Metadata(
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: Option(String),
    userinfo_endpoint: Option(String),
    introspection_endpoint: Option(String),
    revocation_endpoint: Option(String),
    end_session_endpoint: Option(String),
    /// None when the provider omits `code_challenge_methods_supported`.
    code_challenge_methods: Option(List(String)),
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
    audiences: List(String),
    expires_at: Option(Int),
    issued_at: Option(Int),
    not_before: Option(Int),
    token_type: Option(String),
    issuer: Option(String),
    extra: Dynamic,
  )
}

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
