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
  store and custody owner, Keycloak. (Revised by D10 and D13: the gose
  backend is the only backend; oidcc is a test oracle.)
- **Exclusions:** authorization-server implementation, implicit/hybrid/password
  flows, JavaScript target (design §1).

## Current state

- Waves W0–W9 executed (2026-09-30 to 2026-10-01). Branch
  `warden-implementation` (local, not pushed). Repository private; no release
  published.
- One backend: Gleam-native on gose 2.2.0 + kryptos 1.5.0 with Warden's
  transport over OTP `ssl` (D10, D11). The oidcc backend was removed before
  the first release (D13); oidcc 3.9.0 and erlang-jose remain test-only
  oracles. `src/` contains no Erlang.
- Results on the final tree (2026-10-01):

| Suite                                         | Command                                                  | Result                                                                                        |
| --------------------------------------------- | -------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Fast gate                                     | `nix develop -c scripts/check`                           | 72 pass; 13 negative compile cases + positive control; consumer 4 pass                        |
| Keycloak 26.7.5                               | `scripts/keycloak up; WARDEN_SUITE=keycloak gleam test`  | 15 pass (includes raw-oidcc probe P1)                                                         |
| node-oidc-provider 9.12.2 + panva/jose 6.2.12 | `scripts/node-provider up; WARDEN_SUITE=node gleam test` | 7 pass (21-token corpus, 5 client-auth methods, 22-scenario raw-oidcc differential, probe P3) |
| Dex v2.45.1, Ory Hydra v26.2.0                | `scripts/interop up; WARDEN_SUITE=interop gleam test`    | 2 pass                                                                                        |
| Browser (Chrome 154)                          | `scripts/browser-journey`                                | 9/9                                                                                           |
| OIDF RP conformance release-v5.3.1            | `scripts/conformance-suite up; scripts/conformance`      | 34 PASSED, 3 SKIPPED, 3 REVIEW, 1 suite defect                                                |

- Conformance details in [evidence](evidence/conformance/README.md); every
  conformance run uses the **non-default opt-in `AssumeS256WhenUnadvertised`**
  (D7), because the suite's OP omits PKCE metadata. SKIPPED (`alg: none`
  refused), REVIEW (front-channel logout) and the suite defect are not passes.
  The removed oidcc backend's runs are kept under `evidence/**/history/`.
- No open owner decisions. See [decisions.md](decisions.md).

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
| W8   | Native backend (D10), Gleam transport (D11), sinal observations (D12) | Every suite on both backends; default switched           |
| W9   | PKCE opt-in (D7); oidcc backend removed (D13)                         | Every suite on the single backend                        |

## Decision register

See [decisions.md](decisions.md).

## Open decisions

- D7 — Keep requiring advertised S256 (RFC 9700 §2.1.1)? Conformance
  evidence currently relies on an internal harness policy.

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

### W2 — MVP login through Keycloak (closed 2026-09-30)

- Public API: pure `warden/config`, `warden.start`/`supervised`,
  `begin_login`, `complete_login` (query and form-post), custody install and
  recovery. Real Keycloak logins, 8-way callback race → one token request,
  replay/binding/issuer/state/expiry/denial negatives; scripted-provider fast
  suite with store-level lock/expiry, store loss, exchange classification.
- Found and fixed: `process.call` panics (replaced by a non-panicking call);
  startup must ensure OTP applications; provider error bodies leaked into
  oidcc telemetry (transport sanitisation, D3).

### W3 — custody, refresh and remaining operations (closed 2026-09-30)

- Refresh reservation/rotation/retain/continuity/quarantine/publication
  recovery; userinfo, client credentials, introspection, RP logout against
  scripted provider, Keycloak, node-oidc-provider, Dex and Hydra.
- Absent refresh ID token reproduced through Warden: quarantined (D6).

### W4 — hostile corpus and differential (closed 2026-09-30)

- panva/jose corpus of 21 ID tokens; client assertions verified by panva/jose;
  raw-oidcc differential on 22 separate transactions: agreement except the
  two documented stricter policies (extra audience, missing ID token).
- oidcc/jose categorise `none`/HS-confusion as signature/key failures
  (recorded limitation; rejection holds).

### W5 — consumer and browser journey (closed 2026-09-30)

- `consumer/` package (public imports only), reference RP, 9 Chrome
  scenarios. Test PKI moved to OpenSSL (browsers reject pkix_test_data
  certificates).

### W6 — conformance (closed with open decision, 2026-09-30)

- Local suite with verified TLS. Default policy blocks every plan (D7);
  evidence produced under a labelled internal policy. Found and fixed an
  oidcc/jose crash on unusable JWKs (D8) and double discovery (D9).
- Not passed: 3 REVIEW (front-channel logout gap), 1 suite defect
  (third-party initiation).

### W7 — interoperability and operational gates (closed 2026-09-30)

- Dex and Hydra pinned by digest; worker crash/restart, key rotation,
  bounded pending logins, atom and process growth, custody loss during
  refresh.

### W8 — native backend, Gleam transport, typed observations (closed 2026-09-30)

- Owner decisions: gose backend by replacement behind the seam (D10);
  transport in Gleam over OTP `ssl`, http_gun later (D11,
  [handoff prompt](handoff/http-gun-destination-policy.md)); observations
  through sinal (D12).
- Removed `src/warden_http.erl`, `src/warden_ffi.erl` and their Erlang
  tests. The native path has no handwritten Erlang: its `@external`s bind
  OTP functions only (`ssl`, `inet`, `public_key`, `binary`, `erlang`,
  `application`). The one remaining Erlang module, `warden_oidcc.erl`,
  serves the oidcc alternate.
- New modules: `internal/transport`, `internal/oidcc_transport`,
  `internal/protocol`, `internal/backend` (seam), `internal/oidcc_backend`,
  `internal/native/{provider,client,jose}`, `internal/secure`, public
  `warden/observation`.
- Found and fixed: gose rejects JWKs with X.509 members (Keycloak) — members
  stripped (D10 parity note); key-refresh throttle blocked rotation — per-kid
  allowance; verifier needs algorithm-compatible keys only; the native start
  no longer starts the oidcc application; sinal attach before `telemetry`
  starts raises (reference RP starts `telemetry` first; reported in D12).
- Parity: identical verdicts on every suite; differential agrees except the
  two documented stricter policies; native rejection categories are precise.
  D6 resolved (refresh without ID token retains identity).
- Default switched to native after parity. Evidence files now record the
  backend (`backend` field; native conformance in `run-log-native.txt`).
- Distance to target: the oversight design (§1, §3.1, §3.4) still names
  oidcc as default and must be updated for D10; D7 open; sinal and the
  stdlib-1 change are unreleased path dependencies.

### W9 — PKCE opt-in and single backend (closed 2026-10-01)

- D7: public, confidential-client-only `AssumeS256WhenUnadvertised`
  replaced the internal conformance entry point; conformance unchanged.
- D13 (owner decision): oidcc backend removed before the first release;
  oidcc, erlang-jose and telemetry_registry moved to dev-dependencies; the
  oidcc HTTP adapter moved to `test/`; the backend seam collapsed into direct
  calls on the native client.
- Found and fixed: `startup_timeout_ms` was not enforced on the native
  backend (only the oidcc wait loop used it); path dependents failed to build
  once oidcc headers left the dependency graph (records vendored into
  `test/integration/oidcc_records.hrl`); supply-chain record lacked the
  native backend's dependencies.
- Also this wave: history purge of the conformance database (owner
  approved); sinal stdlib widening merged locally; oversight design updated
  (D7, D10–D12, then D13); gose X.509 issue drafted, not filed.
- Distance to target: design release gates (V0 SBOM/changelog review,
  independent security review), sinal and gose releases, durable stores.

## Remaining limitations and gaps

- Production readiness requires the design's release gates and an
  independent security review of Warden-owned code (transport, protocol and
  claim rules, stores); none has been performed. Warden owns more of the
  protocol surface than an oidcc wrapper would. Not certified.
- In-memory stores only: no durable custody, no multi-node replay authority.
- Explicit gaps unchanged (design §4.8): PAR, JAR, DPoP, JWT-bearer, dynamic
  registration, JARM/FAPI, revocation, device grant, token exchange,
  back/front-channel logout; encrypted ID tokens and signed request objects
  are disabled. Third-party initiated login has a route in the reference RP
  but no conformance verdict.
- Secret erasure and crash-dump protection are not provided (application
  duty).
- Clock skew is 0 s; no Warden setting.
- No fallback backend (D13): a native-backend defect has no configuration
  workaround; the oidcc path remains in git history.
- Path dependency `sinal = { path = "../sinal" }` until sinal publishes a
  release with the stdlib widening (merged locally, `098a2d5`).
- gose 2.2.0 rejects JWKs with X.509 members: issue drafted, not filed
  ([draft](handoff/gose-x509-jwk-issue.md)).
- Upstream defects found but not reported: oidcc `has_kid/2` and the
  unusable-key fold (D8; no longer affect Warden).
