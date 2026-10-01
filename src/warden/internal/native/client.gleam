//// Native (gose) backend operations: authorization and logout URLs, code
//// exchange, refresh, userinfo, introspection and client credentials.
////
//// Every response is decoded totally into the shared `protocol` types; only
//// the OAuth `error` code of an error response is kept. Client
//// authentication uses exactly the configured method.

import gleam/bit_array
import gleam/crypto
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/time/timestamp
import gleam/uri
import warden/config.{type Config}
import warden/internal/native/jose
import warden/internal/native/provider.{type Provider}
import warden/internal/protocol.{
  type AuthorizationParams, type Failure, type Introspected, type Metadata,
  type TokenResponse,
}
import warden/internal/redacted.{type Redacted}
import warden/internal/transport

pub type Client {
  Client(
    provider: Provider,
    policy: transport.Policy,
    issuer: String,
    client_id: String,
    method: String,
    credential: Redacted(Option(String)),
    id_token_algorithms: List(String),
    assertion_algorithms: List(String),
    clock: fn() -> Int,
  )
}

pub fn new(
  config: Config,
  provider: Provider,
  policy: transport.Policy,
  clock: fn() -> Int,
) -> Client {
  Client(
    provider:,
    policy:,
    issuer: config.issuer(config),
    client_id: config.client_id(config),
    method: config.authentication_method(config),
    credential: redacted.new(config.trusted_credential(config)),
    id_token_algorithms: config.signing_algorithms(config),
    assertion_algorithms: config.assertion_algorithms(config),
    clock:,
  )
}

pub fn metadata(client: Client) -> Result(Metadata, Failure) {
  provider.snapshot_of(client.provider) |> result.map(fn(s) { s.metadata })
}

// ---------------------------------------------------------------------------
// URLs

pub fn authorization_url(
  client: Client,
  params: AuthorizationParams,
) -> Result(String, Failure) {
  use metadata <- result.try(metadata(client))
  let query =
    [
      #("response_type", "code"),
      #("client_id", client.client_id),
      #("redirect_uri", params.redirect_uri),
      #("scope", string.join(params.scopes, " ")),
      #("state", params.state),
      #("nonce", params.nonce),
      #("code_challenge", s256(params.verifier)),
      #("code_challenge_method", "S256"),
    ]
    |> list.append(case params.response_mode {
      "query" -> []
      mode -> [#("response_mode", mode)]
    })
    |> list.append(params.extension)
  Ok(with_query(metadata.authorization_endpoint, query))
}

pub fn logout_url(
  client: Client,
  id_token_hint id_token_hint: Option(String),
  post_logout_redirect_uri post_logout_redirect_uri: Option(String),
  state state: Option(String),
) -> Result(String, Failure) {
  use metadata <- result.try(metadata(client))
  case metadata.end_session_endpoint {
    None -> Error(protocol.Policy("endpoint_missing"))
    Some(endpoint) ->
      [
        option.map(id_token_hint, fn(v) { #("id_token_hint", v) }),
        Some(#("client_id", client.client_id)),
        option.map(post_logout_redirect_uri, fn(v) {
          #("post_logout_redirect_uri", v)
        }),
        option.map(state, fn(v) { #("state", v) }),
      ]
      |> option.values
      |> with_query(endpoint, _)
      |> Ok
  }
}

fn with_query(endpoint: String, query: List(#(String, String))) -> String {
  let separator = case string.contains(endpoint, "?") {
    True -> "&"
    False -> "?"
  }
  endpoint <> separator <> uri.query_to_string(query)
}

fn s256(verifier: String) -> String {
  crypto.hash(crypto.Sha256, <<verifier:utf8>>)
  |> bit_array.base64_url_encode(False)
}

// ---------------------------------------------------------------------------
// Token endpoint

pub fn exchange_code(
  client: Client,
  code code: String,
  redirect_uri redirect_uri: String,
  nonce nonce: String,
  verifier verifier: String,
) -> Result(TokenResponse, Failure) {
  use #(snapshot, body) <- result.try(
    token_request(client, [
      #("grant_type", "authorization_code"),
      #("code", code),
      #("redirect_uri", redirect_uri),
      #("code_verifier", verifier),
    ]),
  )
  token_response(client, snapshot, body, Some(nonce))
}

pub fn refresh(
  client: Client,
  refresh_token refresh_token: String,
) -> Result(TokenResponse, Failure) {
  // The subject and other continuity rules are checked by Warden's custody
  // owner; an absent refreshed ID token is permitted (OIDC Core §12.2).
  use #(snapshot, body) <- result.try(
    token_request(client, [
      #("grant_type", "refresh_token"),
      #("refresh_token", refresh_token),
    ]),
  )
  token_response(client, snapshot, body, None)
}

pub fn client_credentials(
  client: Client,
  scopes: List(String),
) -> Result(TokenResponse, Failure) {
  let scope = case scopes {
    [] -> []
    scopes -> [#("scope", string.join(scopes, " "))]
  }
  use #(snapshot, body) <- result.try(
    token_request(client, [#("grant_type", "client_credentials"), ..scope]),
  )
  token_response(client, snapshot, body, None)
}

fn token_request(
  client: Client,
  form: List(#(String, String)),
) -> Result(#(provider.Snapshot, Dynamic), Failure) {
  use snapshot <- result.try(provider.snapshot_of(client.provider))
  use endpoint <- result.try(case snapshot.metadata.token_endpoint {
    Some(endpoint) -> Ok(endpoint)
    None -> Error(protocol.Policy("endpoint_missing"))
  })
  use body <- result.try(
    authenticated_post(client, snapshot.metadata, endpoint, form)
    |> provider.json_response
    |> result.map(fn(pair) { pair.0 }),
  )
  Ok(#(snapshot, body))
}

/// POST a form with exactly the configured client authentication.
fn authenticated_post(
  client: Client,
  metadata: Metadata,
  endpoint: String,
  form: List(#(String, String)),
) -> Result(transport.Response, transport.Failure) {
  case client_authentication(client, metadata) {
    Error(Nil) ->
      Error(transport.Failure(transport.NotSent, transport.InvalidRequest))
    Ok(#(extra_form, extra_headers)) ->
      transport.send(
        client.policy,
        transport.Request(
          method: transport.Post,
          url: endpoint,
          headers: [
            #("content-type", "application/x-www-form-urlencoded"),
            #("accept", "application/json"),
            ..extra_headers
          ],
          body: Some(<<uri.query_to_string(list.append(form, extra_form)):utf8>>),
        ),
      )
  }
}

fn client_authentication(
  client: Client,
  metadata: Metadata,
) -> Result(#(List(#(String, String)), List(#(String, String))), Nil) {
  let secret = option.to_result(redacted.reveal(client.credential), Nil)
  case client.method {
    "none" -> Ok(#([#("client_id", client.client_id)], []))
    "client_secret_basic" -> {
      use secret <- result.map(secret)
      // RFC 6749 §2.3.1: form-encode both parts before Base64.
      let credentials =
        uri.percent_encode(client.client_id)
        <> ":"
        <> uri.percent_encode(secret)
      #([], [
        #(
          "authorization",
          "Basic " <> bit_array.base64_encode(<<credentials:utf8>>, True),
        ),
      ])
    }
    "client_secret_post" -> {
      use secret <- result.map(secret)
      #([#("client_id", client.client_id), #("client_secret", secret)], [])
    }
    "client_secret_jwt" | "private_key_jwt" -> {
      use credential <- result.try(secret)
      let key = case client.method {
        "client_secret_jwt" -> jose.SecretKey(credential)
        _ -> jose.PrivateJwk(credential)
      }
      use assertion <- result.map(jose.client_assertion(
        key,
        client.client_id,
        client.issuer,
        client.assertion_algorithms,
        metadata.auth_signing_algorithms,
        random_token(),
        timestamp.from_unix_seconds(client.clock()),
      ))
      #(
        [
          #("client_id", client.client_id),
          #(
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          ),
          #("client_assertion", assertion),
        ],
        [],
      )
    }
    _ -> Error(Nil)
  }
}

fn token_response(
  client: Client,
  snapshot: provider.Snapshot,
  body: Dynamic,
  nonce: Option(String),
) -> Result(TokenResponse, Failure) {
  use raw <- result.try(
    decode.run(body, raw_token_decoder())
    |> result.replace_error(protocol.Malformed),
  )
  use id_token <- result.try(case raw.id_token {
    None -> Ok(None)
    Some(token) ->
      verify_with_refresh(client, snapshot, token, fn(keys) {
        jose.verify_id_token(
          token,
          keys,
          expectations(client, nonce, raw.access_token),
        )
      })
      |> result.map(fn(claims) { Some(protocol.IdToken(token:, claims:)) })
  })
  Ok(protocol.TokenResponse(
    access_token: raw.access_token,
    token_type: raw.token_type,
    expires_in: raw.expires_in,
    refresh_token: raw.refresh_token,
    id_token:,
    id_token_malformed: False,
    scopes: raw.scopes,
  ))
}

fn expectations(
  client: Client,
  nonce: Option(String),
  access_token: Option(String),
) -> jose.Expectations {
  jose.Expectations(
    issuer: client.issuer,
    client_id: client.client_id,
    algorithms: client.id_token_algorithms,
    nonce:,
    access_token:,
    now: timestamp.from_unix_seconds(client.clock()),
  )
}

/// Verify; on an unknown key, refresh the provider's keys once and retry.
fn verify_with_refresh(
  client: Client,
  snapshot: provider.Snapshot,
  token: String,
  verify: fn(_) -> Result(Dynamic, jose.Rejection),
) -> Result(Dynamic, Failure) {
  let rejected = fn(r: jose.Rejection) {
    protocol.IdTokenInvalid(reason: r.reason, claim: r.claim)
  }
  case verify(snapshot.keys) {
    Ok(claims) -> Ok(claims)
    Error(jose.Rejection(reason: "unknown_key", ..)) ->
      case provider.refresh_keys(client.provider, jose.token_kid(token)) {
        Ok(refreshed) -> verify(refreshed.keys) |> result.map_error(rejected)
        Error(_) ->
          Error(protocol.IdTokenInvalid(reason: "unknown_key", claim: None))
      }
    Error(rejection) -> Error(rejected(rejection))
  }
}

type RawToken {
  RawToken(
    access_token: Option(String),
    token_type: String,
    expires_in: Option(Int),
    refresh_token: Option(String),
    id_token: Option(String),
    scopes: List(String),
  )
}

fn raw_token_decoder() -> decode.Decoder(RawToken) {
  let opt_string = decode.optional(decode.string)
  let expires =
    decode.one_of(decode.map(decode.int, Some), [
      decode.map(decode.string, fn(s) { option.from_result(int.parse(s)) }),
      decode.success(None),
    ])
  let scope =
    decode.one_of(
      decode.map(decode.string, fn(s) {
        string.split(s, " ") |> list.filter(fn(x) { x != "" })
      }),
      [decode.list(decode.string)],
    )
  use access_token <- decode.optional_field("access_token", None, opt_string)
  use token_type <- decode.optional_field("token_type", "Bearer", decode.string)
  use expires_in <- decode.optional_field("expires_in", None, expires)
  use refresh_token <- decode.optional_field("refresh_token", None, opt_string)
  use id_token <- decode.optional_field("id_token", None, opt_string)
  use scopes <- decode.optional_field("scope", [], scope)
  decode.success(RawToken(
    access_token:,
    token_type:,
    expires_in:,
    refresh_token:,
    id_token:,
    scopes:,
  ))
}

// ---------------------------------------------------------------------------
// Userinfo and introspection

pub fn userinfo(
  client: Client,
  access_token access_token: String,
  expected_subject expected_subject: String,
) -> Result(Dynamic, Failure) {
  use snapshot <- result.try(provider.snapshot_of(client.provider))
  use endpoint <- result.try(option.to_result(
    snapshot.metadata.userinfo_endpoint,
    protocol.Policy("endpoint_missing"),
  ))
  let response =
    transport.send(
      client.policy,
      transport.Request(
        method: transport.Get,
        url: endpoint,
        headers: [
          #("authorization", "Bearer " <> access_token),
          #("accept", "application/json, application/jwt"),
        ],
        body: None,
      ),
    )
  use claims <- result.try(case response {
    Ok(r) if r.status == 200 ->
      case list.key_find(r.headers, "content-type") {
        Ok("application/jwt" <> _) ->
          bit_array.to_string(r.body)
          |> result.replace_error(protocol.Malformed)
          |> result.try(fn(token) {
            verify_with_refresh(client, snapshot, token, fn(keys) {
              jose.verify_userinfo(
                token,
                keys,
                expectations(client, None, None),
              )
            })
          })
        _ -> provider.json_response(Ok(r)) |> result.map(fn(pair) { pair.0 })
      }
    other -> provider.json_response(other) |> result.map(fn(pair) { pair.0 })
  })
  case protocol.string_claim(claims, "sub") {
    Some(sub) if sub == expected_subject -> Ok(claims)
    _ -> Error(protocol.UserinfoSubjectMismatch)
  }
}

pub fn introspect(
  client: Client,
  token: String,
) -> Result(Introspected, Failure) {
  use snapshot <- result.try(provider.snapshot_of(client.provider))
  use endpoint <- result.try(option.to_result(
    snapshot.metadata.introspection_endpoint,
    protocol.Policy("endpoint_missing"),
  ))
  use #(body, _) <- result.try(
    authenticated_post(client, snapshot.metadata, endpoint, [#("token", token)])
    |> provider.json_response,
  )
  decode.run(body, introspection_decoder(body))
  |> result.replace_error(protocol.Malformed)
}

fn introspection_decoder(body: Dynamic) -> decode.Decoder(Introspected) {
  use active <- decode.field("active", decode.bool)
  case active {
    False -> decode.success(protocol.Inactive)
    True -> {
      let opt_string = decode.optional(decode.string)
      let opt_int = decode.optional(decode.int)
      let scope =
        decode.one_of(
          decode.map(decode.string, fn(s) {
            string.split(s, " ") |> list.filter(fn(x) { x != "" })
          }),
          [decode.list(decode.string)],
        )
      use client_id <- decode.optional_field("client_id", None, opt_string)
      use subject <- decode.optional_field("sub", None, opt_string)
      use username <- decode.optional_field("username", None, opt_string)
      use scopes <- decode.optional_field("scope", [], scope)
      use expires_at <- decode.optional_field("exp", None, opt_int)
      use issued_at <- decode.optional_field("iat", None, opt_int)
      use token_type <- decode.optional_field("token_type", None, opt_string)
      use issuer <- decode.optional_field("iss", None, opt_string)
      decode.success(protocol.Active(
        client_id:,
        subject:,
        username:,
        scopes:,
        expires_at:,
        issued_at:,
        token_type:,
        issuer:,
        extra: body,
      ))
    }
  }
}

fn random_token() -> String {
  crypto.strong_random_bytes(24) |> bit_array.base64_url_encode(False)
}
