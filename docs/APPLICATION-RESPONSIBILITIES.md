# Application responsibilities

Warden verifies identity, binds logins to browsers, owns token custody and
classifies failures. These duties remain with the application.

## Cookies and browser binding

- Warden owns the browser-binding cookie: `warden.login_response` sets
  `__Host-warden_binding` with `Secure`, `HttpOnly`, `Path=/`, no `Domain`,
  `SameSite=Lax` (or `None` for form-post callbacks), a lifetime five
  minutes beyond the pending login, and `Cache-Control: no-store`.
  `begin_login` reuses the cookie a browser already holds, so concurrent
  tabs stay bound. Do not set, rename or relax that cookie.
- `warden.session_reference(session)` is a bearer value. Keep it in a
  signed or encrypted `HttpOnly` cookie or a server-side session, and
  enforce the session lifetime on the server (the reference app signs the
  issue time into the cookie); a browser `Max-Age` is not a limit. Use the
  `__Host-` prefix and set `Secure` unconditionally, not from the request
  scheme: behind a TLS-terminating proxy the application sees plain HTTP.
- Protect state-changing routes (refresh, logout) against cross-site
  requests, for example by requiring `Sec-Fetch-Site: same-origin` or a
  matching `Origin`.
- Send `Cache-Control: no-store` on pages with personal data, and forbid
  framing (`frame-ancestors 'none'`). Warden's login and logout responses
  already carry `no-store`.

## Sessions and storage

- By default the login and session stores are in memory. Sessions and
  pending logins are lost when the Warden supervisor restarts (a lost
  session reads as `SessionLost`), and several nodes need sticky routing.
  For durability or several nodes, give Warden one table through
  `warden/store` (`config.with_custody_store`,
  `config.with_transaction_store`) and a sealing key
  (`config.with_sealing_key`). Check the adapter with
  `warden/testing.check_store`.
- Keep the sealing key in a secret manager. Records are sealed with it
  (AES-256-GCM, bound to their key and version); a database reader learns
  no token, verifier or session reference, and a database writer cannot
  forge or move a session. A writer can still restore an earlier copy of a
  row (for example a session that has since logged out); protect the table
  against unauthorised writes and keep backups as sensitive as the key. To
  rotate, set the new key and pass the old one to
  `config.with_previous_sealing_keys` until every record has been rewritten
  or has expired (at most the absolute session lifetime).
- Warden ends sessions after their absolute or idle lifetime
  (`config.with_session_lifetime`, default 12 h and 1 h without use); an
  expired session reads as `SessionNotFound`. The number of sessions per
  identity is not bounded (decision D14); cap it in the application if the
  product needs that. Call `logout` when the user signs out.
- Rate-limit login starts (`begin_login`) per client address. The built-in
  login store is bounded (`config.with_max_pending_logins`); a sustained
  flood of unauthenticated login starts can still keep it full. A durable
  login store bounds itself (`store.StoreFull`).
- `logout` removes custody first, then revokes the refresh token at the
  provider (RFC 7009, `default_logout()`), then builds the provider logout
  redirect. A failed revocation (`RevocationFailed`) does not keep the
  session; decide whether to alert. With `NoEndSessionEndpoint` the provider
  session remains and the application decides how to inform the user.

## Resource servers

- `warden/resource` validates JWT access tokens (RFC 9068) locally. It
  checks issuer, exact audience, `typ`, algorithm, signature, `exp`, `nbf`,
  `iat` and required scopes. A locally valid token stays valid until it
  expires even if the provider revoked it; use `warden.introspect` where
  revocation must take effect at once.
- `warden.introspect` checks `exp` and `nbf` but not the audience: check
  `TokenInfo.audiences` and `scopes` yourself (Relay's `admit` does).

## Failure handling

- Branch on `warden.login_error_action` and `warden.session_error_action`.
  `Recover` means: pass the carried `CustodyRecovery` or `RefreshRecovery`
  to `recover_custody` or `recover_refresh` promptly. Both hold token
  material in memory; do not persist or log them.
- `RefreshQuarantined` means the provider may have rotated the refresh
  token. Reauthenticate the user; Warden never resends a possibly
  transmitted refresh token. A refresher that dies mid-request quarantines
  its session when its lease (request timeout + two store timeouts + 1 s)
  runs out.
- `ExchangeOutcomeUnknown` and every consumed-login error mean "start a new
  login"; the code is never retried.

## Operations and secrets

- Closures keep secrets out of `string.inspect` and Warden's errors, logs
  and telemetry. They do not protect against VM introspection, remote shells
  or crash dumps: restrict node access, disable or protect `erl_crash.dump`.
- Client secrets, private JWKs and the sealing key come from the
  application's secret store; Warden reads them only where it uses them.
- Trust anchors: production uses `SystemTrust`. `AllowLoopbackForTesting`
  and custom trust anchors are for local test providers (`warden/testing`
  sets both explicitly). Use `with_allowed_hosts` when the provider's hosts
  are known; it restricts host names, not ports. Warden does not check
  certificate revocation.
- Clock: Warden validates `exp` with no tolerance and `iat`, `nbf` and
  `auth_time` with a small tolerance for a provider clock running ahead
  (`config.with_clock_tolerance`, default 5 s). Login and session lifetimes
  and refresh leases are wall-clock Unix time, so a store shared by several
  nodes agrees on them; keep hosts synchronised (NTP).
- `warden/testing` mints tokens with keys it generates. Nothing trusts them
  unless a configuration names the test provider's issuer and root; do not
  ship such a configuration.
