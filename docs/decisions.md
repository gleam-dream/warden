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

## D4 — Stores: in-memory actors (adopted for MVP; superseded by D19)

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
  (first supervisor child; found by name after restarts, gone when
  `warden.stop` returns); startup discovery uses a one-shot client.

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

## D12 — Observations through sinal (owner direction, 2026-09-30; module renamed `warden/telemetry` by D33)

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
  other applications before any request. Resolved in sinal `355b100`:
  `attach`, `observe` and `with_subscriptions` start `telemetry`, so the
  reference RP no longer starts it.
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

## D14 — Session lifetime in custody (owner decision, 2026-10-01; clock revised by D20)

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
- Revisit: when HTTP Gun and Sinal are published, declare major-bounded
  ranges (D18) and rerun every suite.

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

## D18 — Major-bounded dependency ranges (2026-10-02)

- Cross-package review finding SMCP-1: the exact pins `gleam_crypto == 1.6.0`,
  `gleam_time == 1.11.0`, `exception == 2.1.1`, `telemetry == 1.4.2`,
  `gose == 2.2.0` and `kryptos == 1.5.0` stopped applications from resolving
  Warden together with sibling packages (`gleam_crypto` 1.6.0 needs
  `gleam_stdlib >= 1.0`). A library's exact pins become every
  application's pins.
- Decision: each runtime Hex dependency is `>= <evidence version> and
< <next major>.0.0`. Warden uses only public APIs of every dependency (no
  FFI against private records or modules), so no exact pin remains.
  `telemetry` matches sinal, which wraps only public `:telemetry` calls.
  This revises D10's "both need pinning" and D16's "pin exact versions".
- gose and kryptos: the lower bounds are the versions the security evidence
  was recorded on (D7, D10 parity, D11, D13, conformance and interop runs):
  gose 2.2.0, kryptos 1.5.0. `manifest.toml` still locks the versions
  Warden is tested with. A gose or kryptos version newer than the evidence
  version needs the fast, provider and conformance suites rerun before it
  is recorded in [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md); D10's X.509-member
  stripping and exact-audience rule stay in Warden whatever gose does.
- Test-only oracles (`oidcc == 3.9.0`, `jose == 1.11.12`,
  `telemetry_registry == 0.3.2`) stay pinned: they are not installed by
  applications and the differential evidence names those versions.
- The reference RP (`consumer/`) uses ranges for `wisp` and `mist` too.
- Evidence: fast gate (suite, negative compile tests, consumer) passes on the
  resolved manifest, which still selects gose 2.2.0, kryptos 1.5.0,
  gleam_crypto 1.6.0, gleam_time 1.11.0, exception 2.1.1, telemetry 1.4.2 and
  gleam_stdlib 1.0.5 (the newest allowed).
- Revisit: a new gose or kryptos major, or an advisory against a version the
  range admits (raise the lower bound).

## D19 — Storage port: one compare-and-set table (wave 4, 2026-10-03)

- Decision (WARDEN-R1): custody and pending logins run over a public port,
  `warden/store`: `get`, `put(record, expected)` (insert when `None`,
  replace at exactly `Some(version)`) and `delete_expired(now)`. Warden
  keeps the whole protocol (consumption, reservation, settlement,
  publication, tombstones) and needs only atomic compare-and-set on one row;
  a PostgreSQL adapter is one table and three statements. The in-memory
  stores stay the default and implement the same port, so the fast suite
  exercises the durable code path.
- One `Store` type serves both tables (the report sketched two): the
  contract is identical, and keys are prefixed (`session:`, `login:`), so
  one table may hold both.
- Every store call runs in a short-lived process bounded by the store
  timeout; a read that does not finish is `StoreUnavailable`, a write is
  `StoreOutcomeUnknown`, an adapter that raises is the same. A late reply is
  drained after the worker's `DOWN`, so it never reaches the caller's
  mailbox (finding F4 carried over).
- Ambiguity is never resolved by acting twice: an install whose write is
  unknown returns `CustodyUnconfirmed(recovery)` (the same command and
  reference are resubmitted, idempotently); a consumption whose write is
  unknown is `TransactionStoreUnavailable` and sends nothing; a publication
  whose write is unknown returns `RefreshUnconfirmed(recovery)`.
- Conformance: `warden/testing.check_store` (insert-if-absent, CAS at the
  version, stale and absent replaces refused, exact payload round-trip,
  `delete_expired` boundaries, eight concurrent inserts and replaces with
  exactly one winner). A last-write-wins adapter fails it
  (`a_store_without_compare_and_set_fails_the_check_test`).
- Revisit: a store needing multi-row transactions (none so far).

## D20 — Wall-clock lifetimes (wave 4; answers report open question 2)

- Pending logins, session absolute and idle lifetimes, install-recovery
  horizons and refresh leases are wall-clock Unix seconds, replacing D14's
  monotonic clock. A record shared by several nodes, or read after a
  restart, cannot be measured on one node's monotonic clock.
- Consequence: a wall-clock step moves these deadlines. Hosts must run NTP
  (APPLICATION-RESPONSIBILITIES). `exp` checks were always wall-clock.
- The idle period restarts on use with a coalesced write (at most once per
  `min(60 s, idle / 10)`), so reads do not each cost a store write.
- Tests: `login_lifetime_follows_the_wall_clock_test`,
  `use_restarts_the_idle_period_test`, `idle_sessions_end_test`.

## D21 — Sealed records (wave 4, owner decision Q1: sealed for every durable store)

- Every stored record is AES-256-GCM sealed (kryptos over OTP `crypto`)
  with a 96-bit random nonce. The additional data binds the record kind,
  its store key and its version, so a sealed value does not open under
  another key or version: a database writer cannot forge a session or a
  `VerifiedIdentity`, swap two sessions, or replay a record under another
  key. A database reader learns no token, PKCE verifier, nonce or claim.
- Keys are SHA-256 digests (`session:<hex>`, `login:<hex>`): a database
  reader learns no session reference (a bearer value) and no `state`.
- A durable store requires `config.with_sealing_key` (validation:
  `SealingKeyRequired`); the in-memory stores seal with an ephemeral random
  key per client. The sealed format starts with a version byte and an
  8-byte key id (a digest prefix); `with_previous_sealing_keys` keeps
  retired keys for opening, so a rotation signs nobody out.
- Not prevented: a writer restoring an earlier copy of a whole row
  (rollback), for example a session from before its logout tombstone.
  Preventing it needs state outside the store (a monotonic counter or a
  MAC chain). Documented as an application duty: protect writes, treat
  backups as key-sensitive.
- Random-nonce GCM is limited to about 2^32 seals per key; rotate the
  sealing key well before that (each refresh and idle touch seals once).
- A record that does not open answers `SessionRecordUnreadable` /
  `LoginRecordUnreadable`: no exchange, no refresh (fails closed).
- Tests: `records_are_sealed_and_keyed_by_digest_test`,
  `tampered_records_do_not_open_test`, `sealing_keys_rotate_test`.

## D22 — Refresh reservation over a store: leases quarantine (wave 4)

- With a shared store, a process monitor cannot see a refresher on another
  node, so a reservation carries a lease: request timeout + two store
  timeouts + 1 s. A reservation found after its lease ran out becomes
  `Orphaned`, which refuses new reservations as
  `RefreshQuarantined(RefresherLost)` and never releases the generation:
  the dead refresher may already have sent the refresh token, which the
  provider may have rotated. The orphaned dispatch's own publication is
  still accepted (its new tokens are valid).
- A late `SettleNotSent` does not release an orphaned generation; a late
  rejection (`invalid_grant`) records revocation.
- Detection is now at lease expiry instead of process death (seconds
  instead of milliseconds). Security is unchanged: the rule "a possibly
  sent refresh token is never resent" holds.
- Tests: `an_expired_lease_quarantines_but_accepts_its_publication_test`,
  `an_expired_refresh_lease_quarantines_the_generation_test`,
  `concurrent_reservations_admit_one_dispatch_test`.

## D23 — One access operation; waiters never dispatch (wave 4, WARDEN-R2)

- `access_token(client, session)` returns the current token unless it
  expires within the refresh margin (default 30 s), in which case it
  refreshes. A request that finds another's reservation waits up to the
  refresh wait (default 5 s, polling the store with backoff from 20 ms to
  250 ms) and returns the published token; it reserves itself only after
  the winner settled as proven not sent. A session value older than custody
  uses the current revision instead of failing as stale; a forced
  `refresh` on an older value returns the current token without a second
  refresh.
- Failures leave `Ok`: one `SessionError`, classified by
  `session_error_action`. `RefreshReservationRecovery` is deleted: a
  quarantine is custody state, not a property of a value (report open
  question 3, accepted).
- The waiter's bound is the refresh wait, not the lease: it answers
  `RefreshWaitTimedOut` (retry later) rather than holding a request for the
  lease.
- When a margin-triggered refresh decides nothing (its action is
  `RetryLater`: not sent, store unavailable, wait timed out) and the current
  token has not expired, `access_token` returns the current token, so a
  provider outage inside the margin does not fail requests early. Revoked or
  quarantined outcomes are returned as errors. A forced `refresh` never
  falls back (`an_undecided_refresh_keeps_the_unexpired_token_test`).
- Tests: `concurrent_refresh_sends_one_request_test` (8 requests, one
  refresh grant, one token), `refresh_wait_is_bounded_test`,
  `access_token_refreshes_within_the_margin_test`.

## D24 — Session references and lost in-memory sessions (wave 4)

- References are 256 random bits. With the in-memory custody they carry a
  per-start epoch prefix, so a reference from before a restart answers
  `SessionLost` instead of `SessionNotFound` (SSO-1). Durable stores have no
  epoch: a missing record is `SessionNotFound`.
- Logout writes a tombstone kept for the install-recovery horizon (the login
  lifetime); a session record is kept at least that long after creation.
  A late `recover_custody` therefore answers `RecoveryEnded`, and one older
  than the horizon `RecoveryExpired`; neither re-installs (finding F5).

## D25 — Warden owns the binding cookie (wave 4, WARDEN-R4)

- `begin_login` takes the browser's request and reads
  `__Host-warden_binding`; `login_response` sets it with `Secure`,
  `HttpOnly`, `Path=/`, no `Domain`, `SameSite=Lax` (query) or `None`
  (form post), `Max-Age` = login lifetime + 5 min, and
  `Cache-Control: no-store`. Nothing relaxes it. Six cookie duties leave
  APPLICATION-RESPONSIBILITIES.
- `complete_login` takes the callback request: `GET` for query mode, `POST`
  with `application/x-www-form-urlencoded` for form post; any other method
  or content type is `CallbackMalformed` before any store is touched. Only
  a cookie value of Warden's shape (43 base64url characters) is accepted.
- `Callback` and `BrowserBinding` are removed from the public API.

## D26 — RFC 7009 revocation on logout (wave 4, WARDEN-R7; answers open question 4)

- `default_logout()` revokes: custody is removed first, then the refresh
  token (or, without one, the access token) is revoked at
  `revocation_endpoint` with the configured client authentication, then the
  end-session redirect is built. A failed revocation is reported
  (`RevocationFailed`) and never restores custody; a provider without the
  endpoint reports `RevocationUnsupported`.
- The end-session redirect carries the ID token as `id_token_hint`, so it
  is an opaque `LogoutRedirect` holding its URL in a closure:
  `string.inspect` of a logout outcome shows no ID token (wave 1 follow-up).
- Tests: `login_access_refresh_logout_test`,
  `logout_redirect_does_not_inspect_the_id_token_test`.

## D27 — Introspection a resource server can use (wave 4, WARDEN-R8)

- `exp` is checked strictly (no tolerance, as D15 does for ID tokens) and
  `nbf` with the clock tolerance; either failing answers `InactiveToken`.
- A token over 8 KiB is refused as `IntrospectionTokenTooLarge` without a
  request, so a resource server does not read a huge token as "provider
  down"; an empty token is inactive without a request.
- `TokenInfo` gains `audiences` (string or list) and `not_before`, and its
  claims are decoded through `decode_token_claims`. Introspection does not
  check the audience (it has no configured audience); the caller must, and
  Relay's `admit` does. Local validation (D28) checks it.
- A resource-server-only client cannot introspect (no credentials).

## D28 — Resource-server role: local JWT access tokens (wave 4, owner decision D7)

- `warden/resource` validates RFC 9068 access tokens with the started
  client's key cache (an unknown `kid` refreshes keys once, throttled as in
  D10). Order: size (8 KiB, non-empty); compact JWS only (JWE refused);
  `alg` in the allowlist before any key is touched (`none` and HMAC are
  unrepresentable, so a public key cannot be used as an HMAC secret);
  `typ` `at+jwt` or `application/at+jwt` (required by default,
  `allow_any_token_type` opts out); signature with a key whose `kid`
  matches; `iss` exactly the configured issuer; `exp` required and strict;
  `nbf` and `iat` with the clock tolerance; `aud` exactly `[audience]` by
  default (`AudienceIncluded` opts into membership), so a token issued for
  two resource servers cannot be replayed at either; `sub` and `iat`
  required; required scopes from `scope` (string or list) or `scp`.
- Deviation from RFC 9068 §2.2: `client_id` and `jti` are not required
  (Keycloak and others send `azp`); `client_id` falls back to `azp`.
- Errors are typed and classified: `Rejected` (401 `invalid_token`),
  `Forbidden` (403 `insufficient_scope`), `Unavailable` (503, keys not
  loaded); unavailability is never a rejection or an acceptance.
- Relay integration is an adapter function, not a dependency:
  `resource.verifier(validator, token_value, accept, rejected, unavailable)`
  returns the function Relay's `authorization.verifier` takes.
- `config.resource_server(issuer:)` configures a client with no client
  identity: no login, client credentials or introspection.
- Tests: `every_rejection_is_typed_test` (expired, wrong audience, two
  audiences, wrong issuer, `alg: none`, HS256 keyed with the public key,
  unknown `kid`, wrong and missing `typ`), `rotated_key_is_fetched_once_test`,
  `keys_unavailable_is_not_a_rejection_test`.

## D29 — Test support in the package (wave 4, owner decision D12)

- `warden/testing` ships a scripted provider (discovery, keys, token with
  PKCE S256 and rotating refresh tokens, client credentials, userinfo,
  introspection, revocation, end-session), its own PKI from
  `public_key:pkix_test_data` (a CA-issued leaf for `localhost` and
  `127.0.0.1`; OTP refuses a self-signed peer), ES256 signing with gose and
  an HTTPS listener over OTP `ssl`. No new dependency and no handwritten
  Erlang in `src/`.
- It mints tokens, including forged ones (`alg: none`, HMAC with the public
  key, unknown key), with keys generated at start. Nothing trusts them unless
  a configuration names the provider's issuer and root, which only
  `testing.config` and `testing.trusting` do, together with
  `AllowLoopbackForTesting`. No production default changes.
- The listener and state actor are linked to the caller, so a failing test
  cleans them up.

## D30 — Lifecycle: names first, discovery in the background (wave 4, WARDEN-R5)

- `new(config)` validates and allocates every process name once;
  `start(client)` discovers synchronously (startup timeout) and refuses an
  incompatible provider; `supervised(client)` starts at once and discovers
  in the background with backoff from 1 s to 60 s. Until discovery succeeds
  and the metadata passes the compatibility check, every operation answers
  `ProviderNotReady` (fails closed); a provider outage at boot no longer
  fails the parent tree (SSO-10).
- A restart keeps the names, so a captured `Client` stays valid; the
  supervisor registers itself under the client's name, so `stop` finds it.
  `StartError` is no longer flattened: `supervised` reports
  `describe_start_error`.

## D31 — One bound on `complete_login` (wave 4, owner decision)

- `complete_login` has one deadline (default 30 s, `with_login_timeout`):
  each store call, the code exchange and any key refresh get only what is
  left. A deadline reached before the exchange answers `LoginTimedOut` (the
  login is consumed, nothing sent); one reached during installation answers
  `CustodyUnconfirmed`. The previous worst case was about 34 s with no
  single bound.

## D32 — Failure classification by caller action (wave 4, WARDEN-R9)

- `login_error_action` and `session_error_action` return a closed `Action`:
  `Reauthenticate`, `RetryLater`, `Recover`, `FixConfiguration`,
  `RejectRequest`. `Recover` is added to the report's four: a recovery value
  is neither a retry of the same request nor a new login. No uncertain
  outcome maps to `RetryLater` of the same request.
- Transport failures carry `evidence: NotSent | MaybeSent` instead of
  `sent: Bool`. Every error type has a `describe_*` function.

## D33 — Closed, correlated telemetry (wave 4, WARDEN-R10)

- `warden/observation` becomes `warden/telemetry`. HTTP events carry a
  typed `TransportReason` and `Evidence` instead of a string class, plus
  the caller's `correlation`. New `[warden, login]`, `[warden, refresh]`
  and `[warden, logout]` events carry closed outcomes only: no identity,
  token, code or claim.
- `with_correlation(client, correlation)` is a pure view; Warden passes the
  correlation to its HTTP Gun requests, so HTTP Gun's events for the same
  provider calls carry it too (SSO-7, SMCP-9).

## D34 — HTTP Gun's separate bounds (wave 4 follow-up)

- Warden sets only HTTP Gun's request timeout; connect (with DNS and TLS),
  pool checkout, idle read and idle pooled connection keep HTTP Gun's own
  bounds (5 s, 5 s, 30 s, 60 s). A saturated pool or a dead connection
  fails before the request deadline instead of using all of it.
- Provider-cache calls wait one request timeout + 1 s (WARDEN-R11), so a
  slow key refetch no longer reports `UnknownSigningKey` early.

## D35 — The test provider serves a scripted `/authorize` (round 5)

- `warden/testing`'s provider answers `GET` and `POST /authorize` like a
  login page whose user always answers as a `LoginDecision` says:
  `SignIn(subject)` (default `test-user`; the request's `login_hint` names
  the user instead, so one provider serves several users per login) or
  `Refuse(error)`. `with_login` sets it at start, `set_login` after. A test
  browser follows the app's own login redirect over HTTPS and returns to the
  callback, so apps carry no login hook in production code (sso_portal
  `Context.login_response`, secure_mcp `/login`). `testing.authorize`
  remains the in-process path and shares the same validation.
- It never redirects to an unverified place: an unknown `client_id` or a
  redirect URI that is not an absolute `http(s)` URI answers `400` with no
  `Location` (RFC 6749 §4.1.2.1). Other faults of a verified client
  (`response_type` not `code`, no S256 challenge, no state or nonce)
  redirect back with `error=invalid_request`. The provider checks no
  redirect URI registration; Warden's own allowlist (D36) and the code
  exchange's exact `redirect_uri` comparison stay the checks under test.
- `revoke_access_token(provider, token)` revokes one access token for
  introspection and userinfo. A local RFC 9068 validator does not see it:
  JWT access tokens carry no revocation channel, and `warden/resource`
  re-fetches keys only for an unknown `kid`, so key rotation would not be an
  honest substitute either. Tests that need a revoked token refused at once
  use introspection; with local validation they use short lifetimes. The
  resource and testing docs say so, and
  `revoked_access_token_is_seen_by_introspection_only_test` asserts both
  sides.
- `set_access_token_audiences(provider, audiences)` sets the `aud` of
  tokens issued from then on, so an app can name an address it learns only
  after the provider starts.
- Nothing here changes a production default: these are `warden/testing`
  functions, trusted only through `testing.config` and `testing.trusting`
  (D29).
- Tests: `test/warden/testing_authorize_test.gleam`; consumer
  `http_login_test.gleam` drives the reference app's real `/login` and
  `/callback` routes through the provider's page.
- Revisit: an app needing provider sessions (SSO across clients) or
  consent screens in tests.

## D36 — Per-login redirect URI from an exact allowlist (round 5, SSO-10, release report Q9)

- `config.new(redirect_uri:)` stays the ordinary path: one URI, used by
  every login. `config.with_allowed_redirect_uris(config, uris)` adds
  further registered callback addresses, and a login chooses one with
  `LoginOptions(redirect_uri: Some(uri), ..)`. `None` (the default) is the
  configured URI.
- Matching is exact string equality against the configured URI and the
  allowlist: no prefix, wildcard, case, port, trailing-slash or
  percent-encoding equivalence (RFC 9700 §4.1.3). Any
  other URI fails `begin_login` with
  `InvalidLoginOption(RedirectUriNotAllowed)` before anything is stored or
  sent; `login_error_action` maps it to `FixConfiguration`, since the app,
  not the browser, chooses the URI. The error carries no URI, so a value
  derived from request input is not echoed into logs.
- Each allowed URI passes the same rule as the configured one
  (`InvalidAllowedRedirectUri(uri)`), and only a relying party takes them
  (`AllowedRedirectUrisNeedLogin` for `service_client` and
  `resource_server`).
- The chosen URI is stored with the pending login and sent unchanged in the
  token request, so the code is exchanged with exactly the URI the
  authorization request named (RFC 6749 §4.1.3); a login begun for one
  address cannot be completed with another's.
- Tests: `login_chooses_an_allowed_redirect_uri_test` (the chosen URI in the
  authorization request, the provider's redirect and the exchange; eight
  near-miss URIs refused), `allowed_redirect_uris_are_validated_test`,
  consumer `login_chooses_a_registered_redirect_uri_test`.

## D37 — The redirect URI is still known before `warden.new` (round 5, SSO-10)

- Checked: the allowlist does not remove sso_portal's port reservation. The
  portal's handler needs the `Client` before mist binds, so whatever URI
  the client may use must be known before the port is. Removing the
  reservation would need the allowlist to change after `new`.
- Not offered. A `Client` is an immutable value that survives supervisor
  restarts (D30); a later-set redirect URI would live in process state that
  a restart loses (logins then fail until the app sets it again) or in
  global state that outlives the client, and a security-relevant setting
  would change under running logins. In production the redirect URI is the
  registered public address, known at deploy time; the reservation is test
  harness ordering, which the harness owns (a known port, or binding before
  building the handler).
- The test provider's audience, the other reason secure_mcp reserved a port
  first, can now be set after start (D35).
- Revisit: a host framework that hands an app its bound address before the
  handler is built, or a provider registration that the client discovers at
  run time.

## D38 — A wrong-audience token is its own outcome (wave 5, secure_mcp)

- Problem: `resource.verifier` could only return `rejected`, and Warden's
  exact-audience check ran before Relay's, so a token issued for another
  resource got Relay's generic "invalid or expired" 401.
- Relay (43baa65) added `VerificationError.IssuedForAnotherResource`, a 401
  `invalid_token` with "issued for another resource", for a verifier that
  checks the audience itself. Warden now reports the outcome instead of
  folding it into a rejection:
  - `jose.verify_access_token` compares `aud` last, after signature, `iss`,
    `exp`, `nbf`, `iat`, `typ`, `sub` and `iat`. `AudienceMismatch` therefore
    means a token that is valid but for another resource; an expired,
    forged or malformed token is never reported as one.
  - `resource.ErrorKind` gains `WrongAudience` (`error_kind(AudienceMismatch)`).
  - `resource.verifier` takes `on_error: fn(ErrorKind) -> e` instead of the
    two same-typed `rejected:`/`unavailable:` arguments. The caller matches
    every kind, so a 503 cannot be swapped with a 401 by position, and a
    framework with a variant for a wrong audience or a missing scope uses it.
    Relay maps `Rejected | Forbidden` to `BearerRejected`.
- No opt-in policy. The first wave 5 attempt added
  `AudiencePolicy.AudienceCheckedByCaller` (Warden skips `aud`, Relay's
  `admit` compares it). It is deleted: it weakened a check by configuration,
  it needed Relay to do the comparison, and no non-relay use asked for it.
  `ExactAudience` and `AudienceIncluded` are unchanged and fail closed.
- Introspection already returned audiences. The recipe tags its provider
  call with the request's correlation (`warden.with_correlation(client,
correlation)`), so the call joins its MCP request in telemetry. Relay says
  the correlation may come from the client, and Warden uses it only for
  telemetry, never for a decision.
- Tests: `a_wrong_audience_is_reported_only_for_an_otherwise_valid_token_test`,
  `relay_style_verifier_maps_every_kind_test`; `relay_consumer` runs the
  recipe through Relay's `admit` and `challenge`, and checks that an
  introspection call carries the request's correlation.

## D39 — No JWK or JWKS trust anchor for 1.0 (wave 5)

- `config.Trust` is the set of X.509 roots that authenticate the provider's
  TLS endpoints. PEM is the standard text form of a certificate, and the
  only consumer-facing complaint (sso_portal) is that http_gun's `Anchors`
  wants DER, a format question rather than a missing key-pinning feature.
- A JWK or JWKS anchor is a different mechanism: pinning the provider's
  signing keys instead of fetching `jwks_uri`. It would bypass discovery,
  key rotation and the unknown-`kid` refresh (D30), and no app, provider
  profile or conformance case asks for it. Pinned keys without rotation are
  a liability a release should not invite.
- Not added. `Trust` may gain a variant later without breaking callers that
  match on it only to build one; the cost of adding it is not rising.
- Revisit: a provider that publishes no JWKS endpoint, or an application
  that must verify tokens offline against keys it distributed itself.
- The DER half of the complaint is met in `warden/testing`, where the
  certificate already exists in that form: `testing.trust_anchor_der(provider)
-> BitArray` is the root HTTP Gun's `Anchors` takes. `config.Trust` stays
  PEM, since a configuration holds text read from a file or a secret store.
