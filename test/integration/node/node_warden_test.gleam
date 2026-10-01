//// Warden against node-oidc-provider 9.12.2 (`scripts/node-provider up`).
//// ID tokens in the hostile corpus are produced by panva/jose 6.2.12 from
//// the provider's own token for each transaction, so nonce and times belong
//// to that transaction. Client assertions Warden sends are verified
//// independently by panva/jose at the provider.

import gleam/list
import gleam/option.{None, Some}
import gleam/string
import warden
import warden/config
import warden_test_support as support

const issuer = "https://localhost:19443"

const secret = "warden-node-disposable-secret-0123456789"

pub fn settings(
  client_id: String,
  authentication: config.ClientAuthentication,
) -> config.Settings {
  config.new(
    issuer:,
    client_id:,
    redirect_uri: "https://localhost:1/callback",
    authentication:,
  )
  |> config.with_scopes(["email", "profile"])
  |> config.with_trust(config.TrustAnchorsPem(support.ca_pem()))
  |> config.with_destinations(config.AllowLoopbackForTesting)
}

pub fn start(settings: config.Settings) -> warden.Client {
  let assert Ok(validated) = config.validate(settings)
  let assert Ok(client) = warden.start(validated)
  client
}

pub fn basic() -> warden.Client {
  start(settings("warden-rp", config.ClientSecretBasic(config.secret(secret))))
}

pub fn attempt(
  client: warden.Client,
  user: String,
) -> Result(warden.LoginCompletion, warden.LoginError) {
  let options =
    warden.LoginOptions(..warden.default_login(), login_hint: Some(user))
  let assert Ok(redirect) = warden.begin_login(client, None, options)
  let assert Ok(support.Query(query)) = support.authorize(redirect.url, issuer)
  warden.complete_login(
    client,
    warden.QueryCallback(query),
    Some(redirect.browser_binding),
  )
}

/// The hostile ID-token corpus. Expected Warden outcomes; `"ok"` means a
/// completed login.
pub fn corpus() -> List(#(String, String)) {
  [
    #("resign", "ok"),
    #("es256", "ok"),
    #("good_at_hash", "ok"),
    // oidcc 3.9.0 folds verification over the key set and keeps
    // `no_matching_key_with_kid` from keys with other kids, so a tampered
    // token under a known kid is reported as an unknown key (after a JWKS
    // refresh). Still a rejection; the category is upstream's.
    #("bad_signature", "UnknownSigningKey"),
    // Rejected. jose refuses algorithms outside the allowlist before oidcc
    // can name them, so oidcc 3.9.0 reports these as signature or key
    // failures rather than `none_alg_used` / `unsupported_signing_alg`.
    #("alg_none", "BadSignature"),
    #("hs256_confusion", "UnknownSigningKey"),
    #("hs256_client_secret", "BadSignature"),
    #("unknown_kid", "UnknownSigningKey"),
    #("no_kid_wrong_key", "BadSignature"),
    #("wrong_iss", "IdTokenIssuerMismatch"),
    #("wrong_aud", "IdTokenAudienceMismatch"),
    #("extra_aud", "IdTokenAudienceMismatch"),
    #("wrong_azp", "AuthorizedPartyMismatch"),
    #("expired", "IdTokenExpired"),
    #("nbf_future", "IdTokenNotYetValid"),
    #("missing_sub", "MissingClaim(\"sub\")"),
    #("missing_iat", "MissingClaim(\"iat\")"),
    #("wrong_nonce", "NonceMismatch"),
    #("missing_nonce", "NonceMismatch"),
    #("bad_at_hash", "AccessTokenHashMismatch"),
    #("encrypted_unsigned", "EncryptedIdTokenUnsupported"),
  ]
}

pub fn outcome(
  result: Result(warden.LoginCompletion, warden.LoginError),
) -> String {
  case result {
    Ok(warden.LoginCompleted(_)) -> "ok"
    Error(warden.IdentityRejected(problem)) -> string.inspect(problem)
    other -> "unexpected " <> string.inspect(other)
  }
}

pub fn hostile_id_token_corpus_test() {
  support.node_reset()
  let client = basic()
  let results =
    list.map(corpus(), fn(c) {
      support.node_next("authorization_code", [support.NodeIdToken(c.0)])
      #(c.0, outcome(attempt(client, "alice")))
    })
  let mismatches =
    list.zip(corpus(), results)
    |> list.filter(fn(pair) { pair.0 != pair.1 })
  assert mismatches == []
  warden.stop(client)
}

pub fn provider_denial_test() {
  let client = basic()
  let assert Error(warden.ProviderDenied(warden.AccessDenied)) =
    attempt(client, "deny")
  warden.stop(client)
}

pub fn form_post_test() {
  let client =
    start(
      settings("warden-rp", config.ClientSecretBasic(config.secret(secret)))
      |> config.with_response_mode(config.FormPost),
    )
  let assert Ok(redirect) =
    warden.begin_login(client, None, warden.default_login())
  let assert Ok(support.FormPost(body)) =
    support.authorize(redirect.url, issuer)
  let assert Ok(warden.LoginCompleted(_)) =
    warden.complete_login(
      client,
      warden.FormPostCallback(body),
      Some(redirect.browser_binding),
    )
  warden.stop(client)
}

pub fn client_authentication_methods_test() {
  support.node_reset()
  let es =
    config.signing_key_from_jwk(support.pki_file(
      "node-client-client-es256.jwk.json",
    ))
  let rs =
    config.signing_key_from_jwk(support.pki_file(
      "node-client-client-rs256.jwk.json",
    ))
  let assert Ok(es) = es
  let assert Ok(rs) = rs
  let cases = [
    #("warden-rp", config.ClientSecretBasic(config.secret(secret)), "none"),
    #("warden-post", config.ClientSecretPost(config.secret(secret)), "none"),
    #(
      "warden-hs",
      config.ClientSecretJwt(config.secret(secret)),
      "verified:HS256",
    ),
    #("warden-es", config.PrivateKeyJwt(es), "verified:ES256"),
    #("warden-rs", config.PrivateKeyJwt(rs), "verified:RS256"),
  ]
  list.each(cases, fn(c) {
    support.node_reset()
    let client = start(settings(c.0, c.1))
    let assert Ok(warden.LoginCompleted(_)) = attempt(client, "alice")
    let log = support.node_log()
    assert log == [#("authorization_code", c.0, c.2)]
    warden.stop(client)
  })
}

pub fn refresh_cases_through_warden_test() {
  support.node_reset()
  let client =
    start(
      settings("warden-rp", config.ClientSecretBasic(config.secret(secret)))
      |> config.with_transport(
        config.Transport(
          ..config.default_transport(),
          trust: config.TrustAnchorsPem(support.ca_pem()),
          destinations: config.AllowLoopbackForTesting,
          request_timeout_ms: 800,
        ),
      ),
    )
  let session = fn() {
    let assert Ok(warden.LoginCompleted(s)) = attempt(client, "alice")
    s
  }
  // Present ID token, rotation.
  let s = session()
  let assert Ok(warden.RefreshCompleted(s2)) = warden.refresh_session(client, s)
  let assert Ok(warden.RefreshCompleted(_)) = warden.refresh_session(client, s2)
  // Absent ID token: the pinned adapter cannot accept it; quarantined.
  let s = session()
  support.node_next("refresh_token", [support.NodeOmitIdToken])
  let assert Ok(warden.RefreshResponseQuarantined(
    warden.SubjectMismatchOrIdTokenAbsent,
    _,
  )) = warden.refresh_session(client, s)
  let assert Error(warden.RefreshQuarantined) =
    warden.refresh_session(client, s)
  // Omitted refresh token: retained, and the provider still accepts it.
  let s = session()
  support.node_next("refresh_token", [support.NodeDropRefreshToken])
  let assert Ok(warden.RefreshCompleted(s2)) = warden.refresh_session(client, s)
  let r = warden.refresh_session(client, s2)
  assert outcome_refresh(r) == "completed-or-provider-rejected"
  // Changed nonce continuity.
  let s = session()
  support.node_next("refresh_token", [support.NodeIdToken("changed_nonce")])
  let assert Ok(warden.RefreshResponseQuarantined(
    warden.RefreshedNonceMismatch,
    _,
  )) = warden.refresh_session(client, s)
  // Response lost after the provider rotated.
  let s = session()
  support.node_next("refresh_token", [support.NodeDelayMs(2000)])
  let assert Ok(warden.RefreshProviderQuarantined(_)) =
    warden.refresh_session(client, s)
  warden.stop(client)
}

/// node-oidc-provider consumes a refresh token even when the response omits
/// its successor (rotation is server-side), so the retained token may be
/// rejected afterwards. Either outcome is a definite, correctly classified
/// result; neither is silent success.
fn outcome_refresh(
  r: Result(warden.RefreshResult, warden.RefreshError),
) -> String {
  case r {
    Ok(warden.RefreshCompleted(_)) -> "completed-or-provider-rejected"
    Ok(warden.RefreshRejectedByEndpoint(warden.InvalidGrant)) ->
      "completed-or-provider-rejected"
    other -> string.inspect(other)
  }
}
