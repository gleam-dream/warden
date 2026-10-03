# warden

A typed Gleam OpenID Connect relying party and OAuth 2.0 client for
Erlang/OTP. Warden owns discovery, key caching, the provider requests and the
OpenID claim rules; signatures and keys are handled by
[gose](https://github.com/jtdowney/gose) and kryptos, and HTTPS by
[HTTP Gun](https://github.com/gleam-dream/http_gun) (destination policy,
pinned DNS, verified TLS, bounded responses) under Warden's application
policy. The package contains no handwritten Erlang. HTTP Gun and Sinal are
local path dependencies until they are published. [oidcc](https://github.com/erlef/oidcc) 3.9.0 is used only in tests,
as a differential oracle.

Status: **unreleased, pre-production.** The accepted design is
[warden-design.md](https://github.com/gleam-dream/oversight/blob/master/warden-design.md).
Production use requires the design's release gates and an independent
security review of Warden-owned code (transport, protocol and claim rules,
stores). Warden is **not certified**. See [docs/PROGRESS.md](docs/PROGRESS.md) for evidence and
remaining limitations.

## Use

```gleam
import gleam/option.{None, Some}
import warden
import warden/config

pub fn start() -> warden.Client {
  let assert Ok(validated) =
    config.new(
      issuer: "https://login.example.com",
      client_id: "app",
      redirect_uri: "https://app.example.com/auth/callback",
      authentication: config.ClientSecretBasic(config.secret(secret)),
    )
    |> config.with_scopes(["email", "profile"])
    |> config.validate
  let assert Ok(client) = warden.start(validated)
  client
}

// Login start: redirect to `redirect.url`; store the binding in a cookie.
let assert Ok(redirect) = warden.begin_login(client, None, warden.default_login())

// Callback: the raw query string (or form body) and the cookie value.
case warden.complete_login(client, warden.QueryCallback(query), Some(binding)) {
  Ok(warden.LoginCompleted(session)) -> warden.session_identity(session)
  Ok(warden.LoginRecoveryRequired(recovery)) -> // warden.recover_custody
  Error(error) -> // typed warden.LoginError
}
```

Operations: `begin_login`, `complete_login`, `recover_custody`,
`restore_session`, `session_access_token`, `refresh_session`,
`recover_refresh_publication`, `userinfo`, `client_credentials`,
`introspect`, `logout`. Identity is keyed by `(issuer, subject)`;
`decode_claims` decodes verified claims into application types.

A complete reference relying party using public imports only lives in
[`consumer/`](consumer/). Application duties (cookies, storage, secrets)
are listed in [docs/APPLICATION-RESPONSIBILITIES.md](docs/APPLICATION-RESPONSIBILITIES.md).

Warden's HTTP Gun client is labelled `"warden"`. Its `http_gun/telemetry`
events carry `client: Some("warden")`, so an application's node-wide
handler can filter or route Warden's HTTP events by that label.

## Development

```sh
nix develop -c scripts/check                 # fast gate: format, build, tests, negative compile, consumer
scripts/keycloak up && WARDEN_SUITE=keycloak gleam test
scripts/node-provider up && WARDEN_SUITE=node gleam test
scripts/interop up && WARDEN_SUITE=interop gleam test      # Dex, Ory Hydra
scripts/browser-journey                      # real Chrome through the reference RP (needs Keycloak)
scripts/conformance-suite up && scripts/conformance        # OpenID RP conformance plans
```

All providers run locally with disposable keys and credentials and a test CA
generated in `build/test-pki`; nothing uses a public demo server or a
production tenant.
