# Technology and policy decisions

Each entry: decision, status, evidence, revisit trigger.

## D1 — Backend: oidcc 3.9.0 (adopted)

- Pinned `oidcc == 3.9.0` with `jose == 1.11.12`, `telemetry == 1.4.2`,
  `telemetry_registry == 0.3.2` (`manifest.toml` checksums). See
  [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md).
- Evidence: P1 probe against Keycloak; login suites.
- Revisit: a new oidcc release or advisory.

## D2 — Transport: owned bounded HTTP/1.1 adapter (adopted)

- `src/warden_http.erl` implements `oidcc_http_adapter`. Rejected
  alternative: sibling `gleam-dream/http_gun` (no pre-connection DNS/IP
  control; streaming and HTTP/2 not needed for OIDC). Default `httpc` adapter
  rejected: no body bound before allocation, automatic redirects unless
  disabled, no destination policy.
- Evidence: [P2](probes/P2-http-control.md).
- Revisit: need for HTTP/2 or streaming, or `http_gun` gaining a
  destination-policy hook.

## D3 — Boundary narrowing of oidcc behaviour (adopted, stricter than upstream)

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

## D7 — PKCE S256 advertisement required (open, owner decision)

- Evidence: the OpenID conformance suite's RP-test OP (release-v5.3.1) does
  not publish `code_challenge_methods_supported`. Warden's accepted contract
  (design §3.2/§3.3; RFC 9700 §2.1.1 "ensure the AS supports PKCE") rejects
  such providers at startup with `ProviderIncompatible([NoS256])`, so no RP
  plan runs under the default policy.
- Conformance evidence was produced with the internal, non-default
  `warden.start_assuming_s256_for_conformance`: Warden still generates,
  sends and verifies its own S256 challenge and nonce, but tolerates the
  missing advertisement (oidcc is told S256 is supported). Every result from
  it is labelled in `docs/evidence/conformance/`.
- Options: (a) keep the contract and treat conformance runs as evidence under
  a documented harness policy (recommended); (b) add a public, explicit
  opt-in policy for providers that support but do not advertise PKCE;
  (c) require advertisement unconditionally and accept no local conformance
  evidence.

## D8 — Unusable JWKS keys (adopted, Warden fix for an upstream defect)

- jose 1.11.12 keeps unparseable JWKs as `{error, _}` entries in a key set;
  oidcc 3.9.0's signature fold crashes on them when no earlier key matched,
  before its unknown-kid refresh. The suite's key-rotation module exposed it.
- The boundary filters non-key entries from the client context and from the
  refresh callback (RFC 7517 §5). Regression:
  `signing_key_rotation_refreshes_keys_test` fails without the filter.
- oidcc's worker `has_kid/2` also has no clause for a key without `kid` in a
  set position it inspects; not reached by current tests. Both are upstream
  defects to report.

## D9 — Startup performs one discovery (adopted)

- Warden validates the metadata the oidcc worker loaded instead of fetching
  discovery itself first; a diagnostic fetch runs only if the worker is not
  ready after 1.5 s, to return a typed failure. Found by the suite's
  discovery-only modules, which finish on the first request.

## D10 — Gleam-native backend on gose (approved 2026-09-30, in progress)

- Owner decision (session of 2026-09-30): build a Gleam-native backend on
  gose 2.2.0 (Apache-2.0, commit `961324d3`) and kryptos 1.5.0 behind the
  existing backend seam, following design §5: same contract tests, corpus,
  raw-oidcc differential, interoperability and conformance runs before the
  default switches; oidcc stays as the alternate backend for at least one
  release. This **revises the accepted design** (§1, §3.1, §3.4: oidcc as
  default; "no second OIDC core"): Warden will own discovery and JWKS
  caching, token, refresh, userinfo, introspection and logout requests and
  the ID-token claim rules. Cryptography stays in gose/kryptos (Erlang
  `crypto`/`public_key`). The design document in `gleam-dream/oversight`
  needs the corresponding update.
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

## D11 — Transport in Gleam over OTP ssl (approved 2026-09-30)

- gleam_httpc 5.0.0 offers only TLS on/off, redirects and a timeout: no
  custom trust anchors, no body bound before allocation, no destination
  policy, and its FFI raises on unexpected httpc errors. gleam_hackney is
  similar; mug 3.1.0 has no TLS; http_gun lacks pre-connection DNS/IP
  control. The transport is rewritten in Gleam, binding OTP `ssl`, `inet`
  and `public_key` with `@external` and no handwritten Erlang module.
- Later: adopt http_gun once it gains a destination-policy hook
  ([prompt](handoff/http-gun-destination-policy.md)).

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
  `gleam_stdlib < 1.0.0`; branch `gleam-stdlib-1` (commit `77fcbef`, local in
  `gleam-dream/sinal`) widens it to `< 2.0.0` with its 93 tests passing on
  1.0.5. That branch needs merging and a release before Warden can depend on
  a published version.
- The oidcc alternate keeps emitting oidcc's own untyped telemetry events.
- Finding for sinal: `sinal.observe`/`attach` raise (`noproc` from
  `telemetry_handler_table`) when the `telemetry` application is not yet
  running, instead of returning an `AttachError`. The reference RP starts
  `telemetry` itself before attaching (an application duty until sinal
  handles it). `sinal.emit` is unaffected: Warden starts `telemetry` with its
  other applications before any request.
- The native backend starts only `crypto`, `public_key`, `ssl` and
  `telemetry`; it no longer starts the oidcc application.
