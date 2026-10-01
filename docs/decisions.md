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

## D6 — Absent refresh ID token (open, owner decision)

See [P3](probes/P3-refresh.md). The default adapter reports
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
