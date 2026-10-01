# Application responsibilities

Warden verifies identity, binds logins to browsers, owns token custody and
classifies failures. These duties remain with the application.

## Cookies and browser binding

- Store `warden.browser_binding_value(redirect.browser_binding)` in a cookie
  when login starts and pass it back to `complete_login`. Use `HttpOnly`,
  `Secure`, `Path=/`, and `SameSite=Lax` for query responses. Form-post
  responses arrive as cross-site POSTs, so the binding cookie then needs
  `SameSite=None; Secure`.
- Give the binding cookie a lifetime longer than the login lifetime, so an
  expired login is reported as `LoginExpired` instead of
  `BrowserBindingMissing`. Reuse an existing binding for new logins from the
  same browser, so concurrent tabs stay bound (see
  `consumer/src/warden_reference/web.gleam`).
- `warden.session_reference(session)` is a bearer value. Keep it in a
  signed or encrypted `HttpOnly` cookie or a server-side session.

## Sessions and storage

- The built-in transaction store and custody owner are in memory. Sessions
  and pending logins are lost on restart of the Warden supervisor, and a
  deployment of several nodes needs sticky routing or one shared replay
  authority. Durable custody and multi-node replay prevention are not
  provided (design §4.6). A cookie-only (stateless) store would not prevent
  replay.
- Session expiry is application policy. Warden exposes token expiry
  (`session_access_token` returns it) and refresh; it does not end sessions
  on its own.
- Call `logout` to remove custody before redirecting to the provider. With
  `NoEndSessionEndpoint`, the provider session remains and the application
  decides how to inform the user.

## Failure handling

- `LoginRecoveryRequired` and `RefreshPublicationUnresolved` carry recovery
  values that hold token material in memory; recover promptly and do not
  persist or log them.
- Quarantined refresh outcomes (`RefreshProviderQuarantined`,
  `RefreshResponseQuarantined`, `RefreshReservationUnresolved`) mean the
  provider may have rotated the refresh token. Reauthenticate the user;
  Warden never resends a possibly transmitted refresh token.
- `ExchangeOutcomeUnknown` and every consumed-login error mean "start a new
  login"; the code is never retried.

## Operations and secrets

- Opaque values and closures keep secrets out of `string.inspect` and
  Warden's errors, logs and telemetry. They do not protect against VM
  introspection, remote shells or crash dumps: restrict node access, disable
  or protect `erl_crash.dump`, and do not log raw oidcc telemetry
  `exception` metadata (oidcc emits it; Warden cannot filter it).
- Client secrets and private JWKs come from the application's secret store;
  Warden reads them only at the trusted backend boundary.
- Trust anchors: production uses `SystemTrust`. `AllowLoopbackForTesting`
  and custom trust anchors are for local test providers. Use
  `allowed_hosts` when the provider's hosts are known.
- Clock: oidcc validates `exp`/`nbf` with zero clock skew against the node
  clock; keep hosts synchronised.
