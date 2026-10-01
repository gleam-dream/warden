# Technology and policy decisions

Each entry: decision, status, evidence, revisit trigger.

## D1 — Backend: oidcc 3.9.0 (superseded by D10; removed by D13)

- Pinned `oidcc == 3.9.0` with `jose == 1.11.12`, `telemetry == 1.4.2`,
  `telemetry_registry == 0.3.2` (`manifest.toml` checksums). See
  [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md).
- Evidence: P1 probe against Keycloak; login suites.
- Revisit: a new oidcc release or advisory.

## D2 — Transport: owned bounded HTTP/1.1 adapter (adopted; rewritten in Gleam by D11)

- `src/warden_http.erl` implements `oidcc_http_adapter`. Rejected
  alternative: sibling `gleam-dream/http_gun` (no pre-connection DNS/IP
  control; streaming and HTTP/2 not needed for OIDC). Default `httpc` adapter
  rejected: no body bound before allocation, automatic redirects unless
  disabled, no destination policy.
- Evidence: [P2](probes/P2-http-control.md).
- Revisit: need for HTTP/2 or streaming, or `http_gun` gaining a
  destination-policy hook.

## D3 — Boundary narrowing of oidcc behaviour (retired with the oidcc backend, D13)

The native backend never had these behaviours: it builds its own
authorization URL, sends only Warden's S256 challenge, uses the configured
client authentication, and keeps introspection results separate.

The boundary (`src/warden_oidcc.erl`) rewrites the oidcc client context before
every call:

| Upstream default                                                   | Warden policy                                                             | Reason                                                                 |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| Automatic PAR when advertised                                      | Disabled; providers requiring PAR are rejected at startup                 | PAR is a later capability; URL creation must not perform network calls |
| Automatic signed request object when `request_parameter_supported` | Disabled; providers requiring it are rejected                             | JAR is a later capability                                              |
| Plain PKCE when S256 absent                                        | S256 required in metadata; URL checked for Warden's own challenge         | Mandatory S256                                                         |
| Client auth chosen from metadata with silent fallback              | Exactly the configured method                                             | No downgrade or surprise method                                        |
| ID-token algorithms from metadata                                  | Intersection with configured allowlist; `none` and HMAC not representable | Algorithm confusion                                                    |
| Client-assertion algorithms from metadata (may include `none`)     | Intersection with key-derived list, `none` removed                        | No unsigned assertions                                                 |
| Encrypted ID tokens / userinfo, DPoP, mTLS aliases when advertised | Disabled                                                                  | Later capabilities                                                     |
| `trusted_audiences: any`                                           | `[]` (exact client audience)                                              | Design §3.3                                                            |
| `nonce: any` default                                               | retained nonce passed; Warden re-checks                                   | Design §3.3                                                            |
| Introspection `client_self_only: true`                             | `false`, Warden classifies `active`                                       | Inactive ≠ error (P1)                                                  |
| ID token optional in token response                                | Required for login                                                        | Design §3.3                                                            |

## D4 — Stores: in-memory actors (adopted for MVP)

- Transaction store and custody owner are OTP actors under Warden's
  supervisor; each mailbox is the critical section. Durable custody, cookie
  sealing and multi-node replay authority remain application responsibilities
  and open decisions (design §9).

## D5 — Test providers (adopted)

- Keycloak 26.7.5 (`quay.io/keycloak/keycloak@sha256:37dbaf6f…a85`), realm
  `test/providers/keycloak/realm-warden.json`.
- node-oidc-provider 9.12.2 and panva/jose 6.2.12 (MIT), exact versions in
  `test/providers/node-oidc/package-lock.json`.
- OpenID conformance suite `release-v5.3.1` prebuilt images (MIT).

## D6 — Absent refresh ID token (resolved by the native backend, D10)

See [P3](probes/P3-refresh.md). The native backend accepts a refresh
response without an ID token (OIDC Core §12.2): the rotated tokens are
installed and the session identity is retained. A present ID token must keep
`iss`, `sub` and `aud`; a changed subject is quarantined as
`RefreshedSubjectMismatch`. The oidcc alternate still cannot (its refresh
path returns `sub_invalid`) and reports
`RefreshResponseQuarantined(SubjectMismatchOrIdTokenAbsent, _)`.

## D7 — PKCE S256 advertisement (resolved 2026-09-30: explicit opt-in)

- Evidence: the OpenID conformance suite's RP-test OP (release-v5.3.1) does
  not publish `code_challenge_methods_supported`. Warden's default (design
  §3.2; RFC 9700 §2.1.1 "ensure the AS supports PKCE") rejects such providers
  at startup with `ProviderIncompatible([NoS256])`, so no RP plan runs under
  the default policy.
- Owner decision: option (b), a public, explicit opt-in.
  `config.with_pkce_advertisement(_, AssumeS256WhenUnadvertised)` also
  accepts a provider whose metadata **omits** the field. A provider that
  lists methods without `S256` is still refused, and the default stays
  `RequireAdvertisedS256`. The internal
  `warden.start_assuming_s256_for_conformance` is removed; the reference RP
  sets the policy from `WARDEN_ASSUME_UNADVERTISED_S256=1`.
- Security consequences under the opt-in:
  - Warden still generates, sends and checks its own S256 challenge and
    verifier; nothing about the request weakens.
  - Warden cannot know whether the provider enforces the challenge. A
    provider that ignores PKCE silently removes PKCE's protection against an
    intercepted or injected code: the code becomes redeemable without the
    verifier by anyone who also holds the client's credentials.
  - For a confidential client, the attacker additionally needs the client
    authentication, and Warden's mandatory nonce binds the returned ID token
    to this browser's login; RFC 9700 §2.1.1 accepts nonce as the
    code-injection countermeasure for confidential OpenID Connect clients.
    State still prevents login CSRF.
  - For a public client nothing else protects an intercepted code, so
    validation refuses the opt-in with `PublicClient`
    (`UnadvertisedPkceRequiresConfidentialClient`).
  - Access tokens from such a login carry no PKCE assurance. Applications
    that need it for a provider must keep the default policy.
  - Metadata cannot be stripped by a network attacker: discovery is fetched
    over verified TLS from the exact issuer. An attacker controlling the
    issuer's metadata already controls the provider.
- Tests: `unadvertised_pkce_is_accepted_only_by_explicit_policy_test` (absent
  field refused by default, accepted with the opt-in and still sends S256;
  `plain`-only refused under both policies) and
  `unadvertised_pkce_requires_a_confidential_client_test`.

## D8 — Unusable JWKS keys (retired with the oidcc backend, D13)

gose skips unusable keys itself; the oidcc/jose defect below still exists
upstream and is unreported.

- jose 1.11.12 keeps unparseable JWKs as `{error, _}` entries in a key set;
  oidcc 3.9.0's signature fold crashes on them when no earlier key matched,
  before its unknown-kid refresh. The suite's key-rotation module exposed it.
- The boundary filters non-key entries from the client context and from the
  refresh callback (RFC 7517 §5). Regression:
  `signing_key_rotation_refreshes_keys_test` fails without the filter.
- oidcc's worker `has_kid/2` also has no clause for a key without `kid` in a
  set position it inspects; not reached by current tests. Both are upstream
  defects to report.

## D9 — Startup performs one discovery (adopted; native since D13)

The native backend discovers once in `warden.start` and seeds the provider
cache with the result. The text below describes the removed oidcc path.

- Warden validates the metadata the oidcc worker loaded instead of fetching
  discovery itself first; a diagnostic fetch runs only if the worker is not
  ready after 1.5 s, to return a typed failure. Found by the suite's
  discovery-only modules, which finish on the first request.

## D10 — Gleam-native backend on gose (adopted 2026-09-30; sole backend since D13)

- Owner decision (session of 2026-09-30): build a Gleam-native backend on
  gose 2.2.0 (Apache-2.0, commit `961324d3`) and kryptos 1.5.0 behind the
  existing backend seam, following design §5: same contract tests, corpus,
  raw-oidcc differential, interoperability and conformance runs before the
  default switches; oidcc stays as the alternate backend for at least one
  release (condition reversed by D13). This **revises the accepted design** (§1, §3.1, §3.4: oidcc as
  default; "no second OIDC core"): Warden will own discovery and JWKS
  caching, token, refresh, userinfo, introspection and logout requests and
  the ID-token claim rules. Cryptography stays in gose/kryptos (Erlang
  `crypto`/`public_key`). The oversight design was updated accordingly.
- Evidence (scratch probe, panva/jose-generated tokens): gose accepted RS256,
  ES256, EdDSA and kid-less RS256; rejected `alg: none` at parse, HS256
  confusion via Warden's allowlist, PS256 against an RS256-tagged key,
  unknown or wrong keys, expired tokens, wrong issuer and audience; skipped
  unusable JWKs (RFC 7517 §5) including the conformance suite's set. Its
  audience check is "contains", so Warden keeps its exact-audience rule.
- Expected consequences: D6 (refresh without ID token) and D8 (unusable keys)
  are resolved by construction; error categories become precise; the
  oidcc-specific narrowing (D3) is unnecessary for the native backend.
- Risks: larger Warden-owned security surface; gose/kryptos are young,
  single-maintainer packages (CI on OTP 27–29, RFC 7515 vectors, Wycheproof
  in kryptos). Both need pinning and review like oidcc.

## D11 — Transport: Gleam over OTP ssl, then HTTP Gun (HTTP Gun adopted 2026-10-01)

- gleam_httpc 5.0.0 offers only TLS on/off, redirects and a timeout: no
  custom trust anchors, no body bound before allocation, no destination
  policy, and its FFI raises on unexpected httpc errors. gleam_hackney is
  similar; mug 3.1.0 has no TLS; http_gun lacks pre-connection DNS/IP
  control. The transport is rewritten in Gleam, binding OTP `ssl`, `inet`
  and `public_key` with `@external` and no handwritten Erlang module.
- Later: adopt http_gun once it gains a destination-policy hook
  ([prompt](handoff/http-gun-destination-policy.md)).
- 2026-10-01: http_gun implements the hook; validated in isolation against
  `369da4f` ([evidence](evidence/http-gun-adoption/README.md)): not adopted.
  Trust (in-memory anchors), stdlib 1.x and connection-reuse gaps are fixed
  there. Release gate unmet (no published version). Unchanged-test gate
  unmet: four malformed responses are rejected with a coarser class and the
  bare-LF reason-phrase case is accepted; meeting it needs an owner decision
  on those expectations.
- 2026-10-01, adopted (owner decision): the transport runs on HTTP Gun's
  public API, by local path until all packages are published (D16), with the
  five rows accepted (D17). Warden's own DNS, TLS, socket and HTTP parsing
  are removed; `transport.gleam` keeps application policy (HTTPS only, URL
  and header hygiene, 64 KiB request cap, early refusal of an oversized
  declared length, content-encoding refusal), the failure mapping and
  observations. Each Warden client owns a supervised, shared HTTP Gun client
  (first supervisor child; found through a stable key after restarts,
  released by `warden.stop`); startup discovery uses a one-shot client.

### D10 parity evidence (2026-09-30)

- The native backend passes the same suites as oidcc: fast, Keycloak,
  node-oidc-provider (21-token corpus, 5 client-auth methods, 22-scenario
  raw-oidcc differential), Dex/Hydra and the 9-scenario browser journey.
  The differential agrees on accept/reject except the two documented
  stricter policies; rejection categories are now precise
  (`UnsignedIdToken`, `AlgorithmNotAllowed`, `BadSignature`).
- X.509 members in JWKs: gose 2.2.0 rejects a JWK carrying `x5c`, `x5t`,
  `x5t#S256` or `x5u` (Keycloak publishes `x5c` on every key). Warden drops
  those members before parsing and verifies with the bare key material, as
  oidcc does: Warden never trusted the certificate chain, so no check is
  lost. To report upstream: gose should ignore (or optionally validate) X.509
  members instead of rejecting the key.
- Key refresh on an unknown `kid` is throttled per provider: a new `kid`
  refreshes immediately (bounded to 64 remembered kids), a repeated one at
  most once per second.

## D12 — Observations through sinal (owner direction, 2026-09-30)

- Warden's observations are typed `sinal` event descriptors in the public
  module `warden/observation`, emitted with `sinal.emit` over `:telemetry`.
  Applications subscribe with `sinal.observe`/`sinal.attach`/
  `sinal.with_subscriptions` and receive Gleam values, not raw maps.
- `[warden, http, request]`: measurement `duration_ms`; metadata `method`,
  `host`, `path` and `outcome` (`Status(code)` or `Failed(sent, class)` with
  the transport's closed class). Queries, headers and bodies are never
  observed (redaction test covers it).
- sinal is a path dependency on the sibling repository. It pinned
  `gleam_stdlib < 1.0.0`; the widening to `< 2.0.0` is merged into sinal's
  local `master` (commit `098a2d5`, 93 tests passing on 1.0.5, not pushed).
  sinal needs a published release before Warden can depend on a version.
- Finding for sinal: `sinal.observe`/`attach` raise (`noproc` from
  `telemetry_handler_table`) when the `telemetry` application is not yet
  running, instead of returning an `AttachError`. The reference RP starts
  `telemetry` itself before attaching (an application duty until sinal
  handles it). `sinal.emit` is unaffected: Warden starts `telemetry` with its
  other applications before any request.
- The native backend starts only `crypto`, `public_key`, `ssl` and
  `telemetry`; it no longer starts the oidcc application.

## D13 — oidcc backend removed before the first release (owner decision, 2026-10-01)

- Decision: remove the oidcc alternate now instead of after one release with
  the native default. This reverses the D10 condition ("keep oidcc for at
  least one release"). Rationale: no release exists, so no user depends on a
  fallback, and both backends produced identical results on every suite.
- Removed: `src/warden_oidcc.erl` (653 lines), `oidcc_backend.gleam`,
  the backend seam `backend.gleam`, the public `config.Backend` type and
  `config.with_backend`, `RefreshValidationError.SubjectMismatchOrIdTokenAbsent`,
  the boundary tests `test/warden_oidcc_test.erl`, and the second fast-suite
  run. `src/` contains no Erlang. Warden calls the native client directly;
  the shared `protocol` types remain the backend contract.
- Kept as test-only (`[dev-dependencies]`): oidcc 3.9.0 (raw-oidcc
  differential, design gate V4, and the P1/P3 probes), erlang-jose 1.11.12
  (scripted provider token signing, independent of gose), telemetry_registry.
  The oidcc HTTP adapter over Warden's transport moved to
  `test/oidcc_transport.gleam`.
- Found while removing:
  - Gleam compiles a path dependency's `test/` Erlang modules, so the two
    raw-oidcc probes' `-include_lib("oidcc/...")` broke the consumer and
    negative-compile builds once oidcc became dev-only. The record
    definitions are vendored verbatim (Apache-2.0 notices kept) into
    `test/integration/oidcc_records.hrl`. A published package ships no
    `test/`, so this affects only path dependents.
  - `startup_timeout_ms` was enforced only by the oidcc path's wait loop:
    on the native backend a slow provider could hold `warden.start` for two
    request timeouts. Discovery and the first key load now share one
    deadline and report `StartupTimedOut`
    (`startup_is_bounded_by_startup_timeout_test`).
- Revisit: a native-backend defect that would have needed the fallback; the
  oidcc path remains in git history (`9d74e20` and earlier).

## D14 — Session lifetime in custody (owner decision, 2026-10-01)

- Review finding F2: custody entries stayed until `logout`. Sessions now
  have an absolute and an idle lifetime (`config.with_session_lifetime`,
  default 12 hours and 1 hour), measured on the monotonic clock. Every use
  (restore, access token, userinfo, refresh) restarts the idle period;
  expired sessions read as `SessionNotFound` and a sweep every minute evicts
  abandoned ones with their tokens. No capacity refusal: refusing new
  sessions at a bound would trade memory exhaustion for a login denial of
  service.

## D15 — Clock tolerance (owner decision, 2026-10-01)

- Review finding J3: zero skew failed a fraction of logins against providers
  whose clocks run slightly ahead. `config.with_clock_tolerance` (default
  5 s, at most 300 s) applies to `iat`, `nbf` and the `max_age` `auth_time`
  check. `exp` has no tolerance: Warden re-checks it strictly after gose.

## D16 — Unpublished siblings by local path (owner decision, 2026-10-01)

- Warden depends on `http_gun` and `sinal` by path (`../http_gun`,
  `../sinal`) until the owner publishes all packages "once all systems are
  working smoothly". This relaxes D11's "released version" gate for
  development; Warden cannot be published while path dependencies remain.
- Revisit: when HTTP Gun and Sinal are published, pin exact versions and
  rerun every suite.

## D17 — Coarser transport classes accepted (owner decision, 2026-10-01)

- With HTTP Gun, four malformed responses are still rejected (`Sent`) but
  classified `ReceiveFailed`, because Gun reports them only as a peer close
  or a dependency crash: a truncated fixed-length body, an invalid status
  line, a signed `content-length`, a signed chunk size. The public reason is
  `ReceiveFailed`; `TruncatedResponse` is removed (it cannot occur).
- A bare LF inside the status line is read as part of the reason phrase,
  which Gun discards; the body is read to the connection's close. Accepted as
  HTTP Gun's documented limitation: the close-delimited body ends the
  connection, so nothing reaches another request.
- Security is unchanged: every malformed response is still refused or
  confined to its own connection; only diagnostic precision is lower.
