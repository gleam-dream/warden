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
