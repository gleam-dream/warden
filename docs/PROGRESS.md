# Warden implementation tracker

This file is the durable progress record for the Warden program. Read it
before relying on conversation history. Closed-wave entries are append-only.

## Round 9: manual-start snapshot ownership (2026-10-05)

- A public-validator regression failed before production edits: key A was
  accepted, removed by two rotations and rejected; killing only the cache of a
  manually started client made A valid again. The child specification captured
  the original discovery snapshot and replayed it on restart.
- Every cache now starts empty. `warden.start` awaits that cache's first attempt;
  supervised startup keeps background discovery. Both modes use the same cache
  lifecycle, without a seed, extra bootstrap request or coordinator. Existing
  typed startup errors, successful-start readiness and deadlines are preserved.
- Startup owns one bounded first-outcome observation: metadata or a failure,
  never signing keys. It retains that outcome even after background recovery,
  so a slow startup observer cannot miss a first-attempt failure. Supervised
  caches retain the same bounded value without requiring a mode flag.
- Failed startup requests shutdown of the actual tree it created and waits only
  for the remaining deadline. Child exits may follow a timeout return; an
  immediate retry can briefly see `AlreadyStarted` while its supervisor drains.
  Tests await actual tree, cache and network-worker termination before retrying.
- Four added tests cover successive removed keys across two cache restarts,
  unavailable and incompatible restart discovery followed by recovery, retained
  first failure after recovery, and cleanup after timeout, discovery failure and
  incompatibility. All token decisions go through the public resource validator.
  Existing reload tests observe the actual scheduled timer before replaying its
  event, so removal of the seeded test constructor preserves scheduling coverage.

- The unchanged `nix develop --command scripts/check` gate passed: 209 core
  tests, 18 negative compilation fixtures plus the positive control, 13 external
  consumer tests and six compiled Relay-recipe tests. A focused selection of
  lifecycle, existing startup and operational tests passed 38 tests using the
  repository runner's existing timeout scaling.

### Large key-set forwarding measurement

- A local OTP 28 run with four schedulers compared a monitored direct worker
  with the real fetch guardian. Each pair alternated order; five pairs used
  generated public P-256 keys with distinct key identifiers. No external
  credentials or provider requests were involved. Worker-owned terms avoid
  literal-sharing copy shortcuts. The term workload decodes a serialized term
  and delivers it; the parse workload parses actual JWKS JSON and delivers it.
- Median term-decode-and-delivery time, in microseconds:

  | Keys  | Direct worker |  Guardian | Additional time |
  | ----- | ------------: | --------: | --------------: |
  | 1     |          7.46 |     14.18 |            6.72 |
  | 100   |        244.30 |    296.16 |           51.86 |
  | 1,000 |      2,448.96 |  3,003.75 |          554.79 |
  | 5,000 |     14,815.49 | 19,364.45 |        4,548.96 |

- The 5,000-key response was 828,903 JSON bytes, below the existing 1 MiB
  response bound. Its decoded flat term was 2,160,024 bytes. A guardian held
  immediately before forwarding occupied 2,546,568 bytes after garbage
  collection; this excludes worker, cache and transport memory and is not a
  total peak-memory measurement. Costs multiply across concurrent active fetches.
- For 5,000 keys, actual parse-and-delivery medians were 1.435 s direct and
  1.410 s guarded. The five-pair ranges overlapped: 1.412–1.778 s direct and
  1.395–1.691 s guarded. Parsing dominated; these samples do not show a speedup.
  The comparison isolates a direct worker and a guardian, not entire old and
  new Warden releases, and does not establish worst-case or deployment capacity.
  The data justifies recording the copy and allocation cost, not adding another
  storage or sharing abstraction.

## Round 9: provider fetch ownership (2026-10-05)

- Discovery, reload and key refresh now belong to the specific cache process
  that started them. A per-fetch guardian cancels ownerless work; the cache
  observes lost workers without losing its accepted snapshot or remaining busy.
  No public API, package dependency, retry cadence or timeout changed.
- Four behavior regressions failed against the original production code before
  the fix. Nineteen focused lifecycle tests now pass, including public token
  rejection after key rotation/restart, normal exits, stalled HTTPS, public
  `stop`, queued completion after shutdown, discovery/reload recovery, old
  completion/DOWN replay and drained
  process bookkeeping. Test fixture synchronization uses scoped telemetry
  barriers and bounded readiness calls rather than race-masking sleeps.
- The final `nix develop --command scripts/check` gate passed: 205 core
  tests, 18 negative compilation fixtures plus their positive control,
  13 external-consumer tests and six compiled Relay-recipe tests.
- The queued-completion regression also fails against a temporary BEAM
  mutation that restores named completion routing: the guardian panics when
  sending to the removed name. Current process-specific routing exits normally.
- Final-gate validation exposed a second ownership race: hard-killing the client
  supervisor could let its parent restart before old children released their
  names. A controlled barrier on the real HTTP pool reproduced immediate
  restart-budget exhaustion. Startup now joins all previous owned child PIDs
  under the existing absolute startup deadline, with no name takeover or
  retry inflation. Two new regressions cover successful release and bounded
  `StartupTimedOut`; the operational fixtures now stop their owning parent.
  Before the fix, the restart regression failed its parent-alive assertion;
  the deadline regression was cancelled when public startup crashed after a
  named-child start failure. After the fix both return through their expected
  behavior paths, including the typed timeout.
- The restart join adds at most five temporary monitors only during startup,
  removed on success or expiry. It does not enter the measured cache/fetch
  path. A held old child can block the parent supervisor's startup callback
  and management handling up to the configured startup bound (15 s default);
  other running clients' request actors remain independent. Nineteen lifecycle
  and eleven operational tests pass together.
- A guardian adds one process, three lifecycle monitors, one link and a result
  forwarding hop per active fetch. Idle caches add no process or monitor; their
  selector gains a completion channel and monitor-message handling. This is
  local to each cache and does not serialize independent clients.
- The extra result copy scales with the decoded key-set size. The existing
  HTTP response bound remains in force, but this small-fixture benchmark does
  not measure worst-case allocation or latency for a large JWKS.
- `stop` requests supervisor shutdown and waits up to five seconds for exit.
  Returning after that bound does not prove shutdown or join every fetch
  worker; owner exit triggers prompt cancellation independently of a
  provider response or a blocked telemetry observer. Cancellation cannot undo
  an HTTP request the provider has already received.
- The local microbenchmark used OTP 28 with four online schedulers and no
  concurrent stress gate. The baseline revision was `99531f3`. Three warmed
  runs measured 3,000 token validations
  per client and 100 sequential TLS key refreshes. The medians below are
  observations on one machine, not a deployment capacity guarantee.

| Measurement                                      | Before         | After          |
| ------------------------------------------------ | -------------- | -------------- |
| One-client token validations/s                   | 2,568          | 2,528          |
| Four concurrent clients, aggregate validations/s | 9,761          | 9,737          |
| 100 sequential TLS key refreshes                 | 5.232 s        | 5.223 s        |
| One-cache snapshot, paired median                | 20.259 µs/read | 20.230 µs/read |
| Four-cache interleaved snapshots, paired median  | 20.581 µs/read | 20.798 µs/read |

- Snapshot isolation used five alternating before/after pairs in one VM, with
  1,000 warmup reads and 20,000 measured reads per cache. One-cache ranges were
  17.057–20.337 µs before and 19.898–20.346 µs after; four-cache ranges were
  20.324–20.759 µs before and 20.587–21.617 µs after. The four-cache median
  increased by 0.217 µs (1.06%); token-validation and refresh ranges overlapped.
- After explicit garbage collection, cache process memory stayed within
  5,768–8,784 bytes in both the before and after paired samples. Heap allocation
  bins vary: this does not establish a memory improvement. Idle and burst-end caches had no active
  lifecycle monitors or queued messages.
- The benchmark entry points are `benchmark/0` and `snapshot_benchmark/0` in
  `test/warden_fetch_ownership_test.erl`; they are not performance thresholds
  in the correctness gate. Paired runs loaded baseline and current provider
  BEAM code between fully stopped client fixtures in the same VM.
- Migration and lifecycle details: [Round 9](migration-round-9.md).

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

- Waves W0–W12 executed (2026-09-30 to 2026-10-01). Branch
  `warden-implementation` (local, not pushed). Repository private; no release
  published.
- One backend: Gleam-native on gose 2.2.0 + kryptos 1.5.0, HTTPS on HTTP
  Gun by local path (D10, D11, D16). The oidcc backend was removed before
  the first release (D13); oidcc 3.9.0 and erlang-jose remain test-only
  oracles. `src/` contains no Erlang.
- Results on the final tree (2026-10-01):

| Suite                                         | Command                                                  | Result                                                                                        |
| --------------------------------------------- | -------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Fast gate                                     | `nix develop -c scripts/check`                           | 127 pass; 13 negative compile cases + positive control; consumer 8 pass                       |
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
- Internal security review done (W10): 2 high, 12 medium and about 30
  low findings; all high and medium fixed except F2, which needs a
  decision. See [SECURITY-REVIEW.md](SECURITY-REVIEW.md).
- No open owner decisions. F2, J3 and F9 were resolved after the review
  (D14, D15; see [SECURITY-REVIEW.md](SECURITY-REVIEW.md)).

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
| W10  | Internal security review and fixes                                    | [SECURITY-REVIEW.md](SECURITY-REVIEW.md); every suite    |
| W11  | Review follow-ups: session lifetime, clock tolerance, monotonic clock | Every suite                                              |
| W12  | HTTP Gun transport (D11, D16, D17)                                    | Every suite on HTTP Gun                                  |

## Decision register

See [decisions.md](decisions.md).

## Open decisions

None. D7 (PKCE S256 advertisement) was resolved on 2026-09-30 with the
public opt-in `AssumeS256WhenUnadvertised`, and W9 replaced the internal
conformance entry point with it; see [decisions.md](decisions.md#d7--pkce-s256-advertisement-resolved-2026-09-30-explicit-opt-in).

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

### W10 — internal security review (closed 2026-10-01)

- Four parallel read-only reviewers (transport; token verification; login
  and custody; config, secrets and reference app). Every finding was
  reproduced with a failing test before its fix; 16 fix commits
  (`b7a88ca`..`061595d`). Record: [SECURITY-REVIEW.md](SECURITY-REVIEW.md).
- Highs: IP-literal TLS name check disabled (T1); client credentials in
  inspected values (C1); pending-login store flood (F1).
- New internal modules: `redacted` (closure-held secrets), `key_policy`
  (RSA ≥ 2048, Ed25519 only, signing purpose), `fifo`. The call proxy drops
  late replies; the provider cache fetches in the background; custody
  monitors refresh dispatchers and bounds installation replays.
- Reference app: `__Host-` cookies, always `Secure`, same-origin POSTs,
  server-enforced session lifetime, security headers.
- Deferred: F9 (monotonic login lifetimes), J10 (key refresh on
  `bad_signature` with an unmatched kid); accepted: T5 (close-delimited
  truncation). Open decisions: F2, J3.

### W11 — review follow-ups (closed 2026-10-01)

- Owner decisions: session lifetime in custody (D14, F2), clock tolerance
  for `iat`/`nbf`/`auth_time` (D15, J3); F9 fixed: the client keeps a
  monotonic clock for login and session lifetimes and the wall clock for
  token validation.
- Each change test-first (`3057c47`, `6950b4f`, `b1cf370`).

### W12 — transport on HTTP Gun (closed 2026-10-01)

- Validated HTTP Gun in isolation (`b517725`, then `369da4f` after G1–G3
  were fixed upstream); adopted by local path (D16) with five coarser
  transport classes accepted (D17).
- Warden's DNS, TLS, socket and HTTP parsing removed; `transport.gleam`
  keeps application policy and the failure mapping. Each Warden client owns
  a supervised shared HTTP Gun client; startup discovery uses a one-shot
  client. Public `TransportReason.TruncatedResponse` replaced by
  `ReceiveFailed`.
- New tests: pooled reuse, replacement after a peer close, restart, released
  pool, caller death, stalled peer, mailbox, metadata, IPv6 Host header,
  client pool ownership; test PKI gains an IPv6 leaf.
- Found on the way: the raw-oidcc differential helper still called a module
  deleted in D13, masked by a stale compiled beam (fixed).

### W13 — release API redesign (release wave 4, 2026-10-03)

- WARDEN-R1 to R11 and the resource-server role (decisions D19 to D34):
  opaque `Config` with `Duration` setters; `new`/`start`/`supervised` with
  restart-stable names and background discovery; a `warden/store` port with
  sealed records and leases; `access_token`/`refresh`/`recover_refresh`
  with a 30 s margin and a 5 s shared wait; gleam_http login boundary with
  Warden-owned binding cookie; RFC 7009 revocation on logout and a redacted
  logout redirect; hardened introspection; `warden/resource` (RFC 9068);
  `warden/testing`; `warden/telemetry` with correlation; one 30 s bound on
  `complete_login`; HTTP Gun's separate connect, pool and idle bounds.
- Fast gate: 174 tests, 18 negative compile cases + positive control,
  consumer 11 tests. The Keycloak, node-oidc-provider, Dex/Hydra, browser
  and conformance suites were migrated to the new API and compile, but were
  not rerun in this wave (they need the local provider containers).
- Migration guide: [migration-wave-4.md](migration-wave-4.md).

### W14 — test login page and per-login redirect URI (round 5, 2026-10-03)

- `warden/testing` serves a scripted `/authorize` (`LoginDecision`,
  `with_login`, `set_login`, `login_hint`), revokes single access tokens and
  sets the access-token audience after start (D35). A login may choose its
  redirect URI from an exact allowlist (`config.with_allowed_redirect_uris`,
  `LoginOptions.redirect_uri`, `RedirectUriNotAllowed`) (D36); the redirect
  URI stays fixed at `warden.new` (D37).
- Fast gate: 183 tests (8 new), negative compile cases unchanged, consumer
  13 tests (2 new: an HTTP-level login through the reference app's routes,
  and a per-login redirect URI).
- Migration guide: [migration-round-5.md](migration-round-5.md).

## Remaining limitations and gaps

- Production readiness requires the design's release gates and an
  independent security review of Warden-owned code (an internal review,
  W10, is not a substitute) (transport, protocol and
  claim rules, stores); none has been performed. Warden owns more of the
  protocol surface than an oidcc wrapper would. Not certified.
- Durable stores are an application adapter over `warden/store` (none is
  shipped); a database writer can roll a sealed row back to an earlier copy
  (D21).
- Explicit gaps unchanged (design §4.8): PAR, JAR, DPoP, JWT-bearer, dynamic
  registration, JARM/FAPI, device grant, token exchange,
  back/front-channel logout; encrypted ID tokens and signed request objects
  are disabled. Third-party initiated login has a route in the reference RP
  but no conformance verdict.
- Secret erasure and crash-dump protection are not provided (application
  duty).
- Clock tolerance 5 s for `iat`/`nbf`/`auth_time` (configurable); none for
  `exp`.
- No fallback backend (D13): a native-backend defect has no configuration
  workaround; the oidcc path remains in git history.
- Path dependencies `http_gun` and `sinal` until both are published (D16);
  Warden cannot be published before then.
- gose 2.2.0 rejects JWKs with X.509 members: issue drafted, not filed
  ([draft](handoff/gose-x509-jwk-issue.md)).
- Upstream defects found but not reported: oidcc `has_kid/2` and the
  unusable-key fold (D8; no longer affect Warden).
