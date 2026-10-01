# Warden implementation tracker

This file is the durable progress record for the Warden program. Read it
before relying on conversation history. Closed-wave entries are append-only.

## Program contract

- **Target:** the accepted design in `gleam-dream/oversight` —
  `warden-design.md`, `PUBLIC-API-GUIDELINES.md`, Warden's rows in
  `PUBLIC-API.md` and `API-COVERAGE.md`, `research/warden-verification-contract.md`
  and `research/warden-refresh-contract.md`, plus the interface-lab
  experiments (`LOGIN-TRANSACTIONS`, `LOGIN-CONSUMPTION`, `VERIFIED-LOGIN`,
  `SESSION-CUSTODY`, `SESSION-REFRESH`).
- **Approval:** the owner's program request (session of 2026-09-30) approves
  implementation against that accepted design, with the stated delivery order:
  real Keycloak login with atomic replay protection and negative tests first;
  then custody/refresh and the remaining baseline operations; then the
  conformance and operational gates. Material contract changes need the
  owner's decision (see "Open decisions").
- **MVP:** a browser user starts login at a public-API reference application,
  authenticates at a pinned local Keycloak over verified TLS, returns through a
  query or form-post callback, and receives a verified `(issuer, subject)`
  identity in a confirmed custody session. Replay, concurrent callbacks, bad
  state/issuer, and expiry are rejected with typed outcomes.
- **Real at MVP:** oidcc 3.9.0 exchange and ID-token validation, entropy,
  PKCE S256, owned bounded HTTPS transport, the in-memory atomic transaction
  store and custody owner, Keycloak.
- **Exclusions:** authorization-server implementation, implicit/hybrid/password
  flows, JavaScript target (design §1).

## Current state

- Wave: **W2 MVP login** — real Keycloak login through the public API passes
  (10 tests incl. 8-way race → one token request). Next: unit/property tests
  for the pure parts, negative compiler tests, store race/expiry tests at the
  lock, then W3.
- Commands: `nix develop -c scripts/check` (fast gate);
  `scripts/keycloak up` then `WARDEN_SUITE=keycloak gleam test`;
  `scripts/node-provider up` then `WARDEN_SUITE=node gleam test`.

## Wave map

| Wave | Purpose                                                               | Exit evidence                                            |
| ---- | --------------------------------------------------------------------- | -------------------------------------------------------- |
| W0   | Environment, pins, gate                                               | `scripts/check` green; supply-chain record               |
| W1   | Executable probes P1–P4                                               | Probe tests and notes under `docs/probes/`               |
| W2   | MVP login through Keycloak                                            | Keycloak login test, race/expiry/negative tests          |
| W3   | Custody, refresh, userinfo, client credentials, introspection, logout | Runtime tests against Keycloak and the scripted provider |
| W4   | Hostile provider, JOSE corpus, raw-oidcc differential                 | Corpus results with recorded policy differences          |
| W5   | Consumer package, reference RP, browser journey                       | Consumer builds from public imports; browser run log     |
| W6   | OIDF RP conformance                                                   | Plan logs or a documented infrastructure gap             |
| W7   | Hydra/Dex interoperability, operational gates                         | Versions, results, remaining gaps                        |

## Decision register

See [decisions.md](decisions.md).

## Open decisions

(none yet)

## Closed waves

### W0 — environment and pins (closed 2026-09-30)

- Dev shell (Gleam 1.18.1, OTP 28, rebar3 3.27.0) builds oidcc 3.9.0 from Hex;
  Hex source equals the signed tag. Supply chain recorded in
  [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md). Fast gate `scripts/check`.
- Suite runner `test/warden_test_runner.erl`: provider suites never fall
  back to or count as the fast suite.

### W1 — executable probes (closed 2026-09-30)

- P1 [oidcc calls](probes/P1-oidcc-calls.md): automatic PAR/JAR, plain-PKCE
  fallback, metadata-driven client auth with silent fallback, secret-bearing
  error terms, introspection conflation. All neutralised in the boundary
  (decision D3).
- P2 [HTTP control](probes/P2-http-control.md): oidcc's adapter seam gives
  full transport control; owned adapter adopted (D2). Sibling `http_gun`
  evaluated and not adopted (no DNS pinning; no streaming/H2 need).
- P3 [refresh](probes/P3-refresh.md): absent refresh ID token reproduced
  against pinned oidcc (`sub_invalid` after provider rotation) — open
  decision D6.
- P4 conformance: OIDF suite `release-v5.3.1` prebuilt images pulled; runs
  locally in dev mode without a token; plan/module inventory recorded in
  [P4](probes/P4-conformance.md).
- Revised plan: none of the probes changed the accepted security contract;
  D6 needs an owner decision to _extend_ capability.
