# Application responsibilities

Warden owns checked OIDC/OAuth evidence and user-token custody. The application chooses how those facts authorize its requests. The [design layer](design/design.typ) specifies the protocol models and invariants; this guide records the decisions a consumer must make.

## Mount and browser origin

- Mount login, callback and logout routes at the configured public origin. Register every exact callback URI with the issuer; select per-login redirects only from the admitted allowlist. Reverse-proxy handling must preserve the intended public scheme, host and path.
- Pass the incoming request to `begin_login` and the configured query or form-post request to `complete_login`. Use `login_response` and `logout_response` for Warden's response headers. For form post, admit the body only on the callback route and enforce a body limit before buffering it.
- Keep Warden's browser-binding cookie intact. It binds a callback; it is not the application's authenticated session. Choose a protected application session cookie with an appropriate lifetime and origin policy, and prevent session fixation when login completes.
- Protect state-changing application routes, including logout, with the application's CSRF/origin policy. Bound login admission, callbacks and session use with application rate limits. Warden's pending-login capacity does not bound all application traffic or session count.
- A third-party initiation route must validate issuer/client selection and the target link. A URL from that request cannot establish a redirect or permission policy.

## Identity and business permission

- Use `(issuer, subject)` as the authentication key. An optional email claim is neither a stable identity key nor proof of application permission.
- Define the application's users, tenants, roles, resource ownership and approver policy. Project `VerifiedIdentity` or caller-decoded claims into those types after successful login. Apply permission checks on every protected operation.
- For a resource server, choose the accepted audience, algorithms, token type and scope policy. Local JWT validation cannot observe immediate provider revocation. Choose introspection when that authority is required and apply audience/permission checks to its returned facts.
- When composing with Relay, let Relay own the audience, required-scope and challenge policy appropriate to its admission path. Keep provider unavailability distinct from rejected bearer evidence. The [compiled Relay recipes](../README.md#resource-servers) show this projection.

## Token custody and persistence

- Retain `session_reference` in the protected application session and restore it for later requests. Treat the reference as a bearer secret. Keep provider access, refresh and ID-token values out of application cookies, URLs, logs and ordinary error pages.
- Choose in-memory or durable stores before startup. In-memory custody is lost on restart. A durable adapter must implement the documented atomic version CAS and report unavailable versus unknown outcome honestly. Run `testing.check_store` and deployment-specific race, crash and durability checks.
- Protect database writes and backups against record rollback. Sealing authenticates a record but does not establish monotonic history after whole-row restoration. Choose the application's rollback authority where that threat matters.
- Supply sealing keys from trusted secret storage, distribute the admitted current/previous key ring consistently across nodes, and rotate before nonce use becomes unsafe. Retain old keys for the records the deployment still intends to open. Destroying a required old key makes those records unreadable.
- Synchronize host clocks. Durable login/session lifetimes use wall-clock time; operational time budgets use monotonic time. The [expiry atomicity ruling](design/design.typ) records the unresolved distinction between expiry admission and a delayed CAS commit.

## Refresh and request retry

- Use `access_token` for the current usable user token. Concurrent refresh belongs to Warden; callers do not reserve, resend or repair a rotating token themselves.
- Use the closed `Action` projections for stable failure handling. Reauthenticate after terminal login failures or refresh quarantine. Submit the carried custody/publication recovery for `Recover`; it retries publication and never the provider exchange. Preserve the recovery value for the application's chosen response path.
- After a resource response, choose whether the application request can safely be repeated. A forced `refresh` is appropriate only when the application has that retry authority; it does not make a resource-side effect idempotent. A possibly sent authorization code or refresh token is never retried.
- Choose caching and concurrency policy for service tokens separately. `client_credentials` performs one grant per call, returns optional expiry, and creates no user session. An absent expiry requires an explicit cache policy.
- Remove the application's own session on logout. Inspect local-custody failure separately from the returned provider revocation and redirect outcomes; provider failure cannot restore ended custody.

## Resource lifetime and observability

- Create client handles once at trusted setup and supervise them under an application parent. Stop a supervised client through that parent. A cache restart needs fresh discovery; a stable handle does not imply provider readiness.
- Keep adapter connections and other captured resources alive until all admitted operations have the completion boundary the application requires. `stop` observes supervisor exit for at most five seconds and returns `Nil` on expiry; it is not a completion receipt for fetch workers or external effects. Pending design rulings preserve this limit.
- Do not assume `complete_login`'s propagated admission deadline is a strict return-latency guarantee: timed-out store cleanup and synchronous telemetry can add latency. Bound application request handling according to the documented boundary and assess the pending verification for a stricter requirement.
- Use `describe_*` errors and the typed Sinal events. Correlation supports observation and carries no authentication authority. Keep telemetry handlers bounded; they run synchronously. Protect tracing, crash dumps, VM inspection and privileged host access separately.
- Use explicit local test-provider trust only in tests. Production endpoints require the intended issuer, destination policy and TLS trust. Host allowlists restrict names; outbound ports need deployment network policy when the application requires it.

The reference consumer's [route protection](../consumer/src/warden_reference/protect.gleam) and [web routes](../consumer/src/warden_reference/web.gleam) exercise these boundaries. Decision history lives in [ADRs](adr/0006-application-authorization-boundary.md).
