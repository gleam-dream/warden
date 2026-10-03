//// Secret sentinels: errors, logs and telemetry never contain authorization
//// codes, state, nonce, PKCE verifiers, client secrets, tokens, raw claims
//// or provider error descriptions.

import gleam/dict
import gleam/http/response
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import warden
import warden/config
import warden/internal/custody
import warden/internal/logins
import warden/internal/secure
import warden_login_test.{browser, callback, param, start}
import warden_test_support as support

@external(erlang, "warden_capture_ffi", "start")
fn capture_start() -> Nil

@external(erlang, "warden_capture_ffi", "stop")
fn capture_stop() -> Nil

@external(erlang, "warden_capture_ffi", "contains")
fn captured(needle: String) -> Bool

fn sha256_hex(value: String) -> String {
  secure.sha256_hex(value)
}

fn binding_of(redirect: warden.LoginRedirect) -> String {
  let assert Ok(cookie) =
    response.get_header(
      warden.login_response(response.new(200), redirect),
      "set-cookie",
    )
  let assert Ok(#(pair, _)) = string.split_once(cookie, ";")
  let assert Ok(#(_, value)) = string.split_once(pair, "=")
  value
}

pub fn no_secret_reaches_errors_logs_or_telemetry_test() {
  capture_start()
  let provider = support.provider_start(support.Standard)
  support.set_claims(
    provider,
    dict.from_list([
      #("name", "SENTINEL-CLAIM-NAME"),
      #("preferred_username", "SENTINEL-CLAIM-USER"),
    ]),
  )
  let client =
    start(
      config.new(
        issuer: support.provider_issuer(provider),
        client_id: "warden-rp",
        redirect_uri: "https://app.example/callback",
        authentication: config.ClientSecretBasic(config.secret(
          "SENTINEL-CLIENT-SECRET",
        )),
      )
      |> config.with_trust(config.TrustAnchorsPem(support.ca_pem()))
      |> config.with_destinations(config.AllowLoopbackForTesting)
      |> config.with_signing_algorithms([config.Rs256]),
    )
  let issuer = support.provider_issuer(provider)

  // Collect every secret a flow creates, then run it to an error.
  let run = fn(code: String, behaviour: option.Option(support.Behaviour)) {
    let assert Ok(redirect) =
      warden.begin_login(client, browser(), warden.default_login())
    let state = param(warden.login_url(redirect), "state")
    let nonce = param(warden.login_url(redirect), "nonce")
    let assert Ok(logins.Found(material:, ..)) =
      logins.get(client.logins, "login:" <> sha256_hex(state))
    support.issue_code(provider, code, nonce)
    case behaviour {
      Some(b) -> support.script(provider, support.Code(code), b)
      None -> Nil
    }
    let result =
      warden.complete_login(
        client,
        callback(redirect, [
          #("code", code),
          #("state", state),
          #("iss", issuer),
        ]),
      )
    #(result, [code, state, nonce, material.verifier, binding_of(redirect)])
  }

  let #(r1, s1) =
    run("SENTINEL-CODE-NONCE", Some(support.IdToken("wrong_nonce")))
  let assert Error(warden.IdentityRejected(warden.NonceMismatch)) = r1
  let #(r2, s2) =
    run("SENTINEL-CODE-REJECT", Some(support.Status(400, "invalid_grant")))
  let assert Error(warden.ExchangeRejected(warden.InvalidGrant)) = r2
  let #(r3, s3) = run("SENTINEL-CODE-AUD", Some(support.IdToken("wrong_aud")))
  let assert Error(warden.IdentityRejected(_)) = r3
  let #(r4, s4) = run("SENTINEL-CODE-UNKNOWN", Some(support.Status(502, "x")))
  let assert Error(warden.ExchangeOutcomeUnknown) = r4
  let #(r5, s5) = run("SENTINEL-CODE-OK", None)
  let assert Ok(session) = r5

  // A denial with a secret-looking description.
  let assert Ok(redirect) =
    warden.begin_login(client, browser(), warden.default_login())
  let denial =
    warden.complete_login(
      client,
      callback(redirect, [
        #("error", "access_denied"),
        #("error_description", "SENTINEL-DESCRIPTION"),
        #("state", param(warden.login_url(redirect), "state")),
        #("iss", issuer),
      ]),
    )

  // Refresh and userinfo errors.
  let assert Ok(access) = warden.access_token(client, session)
  let access = access.token
  let issued_refresh_tokens = support.refresh_tokens(provider)
  let assert Ok(snapshot) =
    custody.get(client.custody, warden.session_reference(session))
  let assert Some(refresh_token) = snapshot.entry.tokens.refresh_token
  support.script(
    provider,
    support.Refresh(refresh_token),
    support.IdToken("changed_nonce"),
  )
  let refreshed = warden.refresh(client, session)
  support.script(provider, support.Userinfo, support.Sub("SENTINEL-OTHER-SUB"))
  let info = warden.userinfo(client, session)

  let errors =
    [
      string.inspect(r1),
      string.inspect(r2),
      string.inspect(r3),
      string.inspect(r4),
      string.inspect(denial),
      string.inspect(refreshed),
      string.inspect(info),
    ]
    |> string.join("\n")
  let secrets =
    list.flatten([s1, s2, s3, s4, s5])
    |> list.append([
      "SENTINEL-CLIENT-SECRET",
      "SENTINEL-CLAIM-NAME",
      "SENTINEL-CLAIM-USER",
      "SENTINEL-DESCRIPTION",
      "SENTINEL-PROVIDER-DESC",
      "SENTINEL-OTHER-SUB",
      warden.access_token_value(access),
      refresh_token,
    ])
    |> list.append(issued_refresh_tokens)
  list.each(secrets, fn(secret) {
    assert #(secret, string.contains(errors, secret)) == #(secret, False)
    assert #(secret, captured(secret)) == #(secret, False)
  })
  capture_stop()
  warden.stop(client)
  support.provider_stop(provider)
}
