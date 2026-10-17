# Testing Warden

## Local checks

- Run `nix develop -c scripts/check` for the complete local gate below. Gleam resolves its pinned Git dependencies; it requires no provider container or external issuer. Run `nix develop -c scripts/check full` to additionally execute all four disposable provider/browser suites. Full requires Docker Compose and installed Google Chrome.
- Run `nix run .#design-gate-render -- docs/design docs/design/design-layer.pdf`, then `nix run .#design-gate-check -- docs/design .` after editing design sources or ADRs. Estimate context with `nix run .#design-gate-context -- docs/design --estimate`; use the manifest and digest to select a section.
- Use `warden/testing` for explicitly trusted local HTTPS issuer scripts and `testing.check_store` for the conditional-write port. Deployment adapters still require database-specific lock, crash, durability and rollback tests. Include a wait crossing the guarded deadline and a lost commit acknowledgement; the generic checker cannot create a database lock wait.

## Fresh root builds on OTP 29

- The frozen test-only JOSE 1.11.12 oracle uses unary `catch`, which OTP 29
  deprecates. Its warnings-as-errors build requires the scoped compiler option
  below; the pin and upstream source remain unchanged.
- Run this sequence inside `nix develop` for a fresh root build and fast tests.
  The option applies only to `gleam build`; the authored Erlang check and tests
  run without it.

```sh
ERL_COMPILER_OPTIONS='[nowarn_deprecated_catch]' gleam build --warnings-as-errors
scripts/erlang-check
WARDEN_SUITE=fast gleam test
```

- `scripts/check`, `scripts/provider-check` and `scripts/benchmark` apply the
  scoped build and unflagged authored Erlang check before their selected tests
  or measurements. Separate consumers do not inherit the root's test-only
  oracle and need no compiler option.
- Do not export the option in the shell. `scripts/erlang-check` must retain
  `erlc -Werror` for authored Erlang, including deprecated unary `catch`.

## Conditional-write evidence

- `check_store` checks all three conditions, exact retained bytes and metadata on
  refusal, conflict precedence, missing rows and concurrent guarded admission.
- Native store tests suspend the memory actor, observe a queued write, advance
  its clock to exact expiry, and verify refusal after the actor resumes. Port
  timeout tests preserve unknown write outcomes for guarded calls.
- The separate consumer uses a two-second login lifetime and a 2.5-second store
  delay. Timing assertions require admission before expiry and the write after
  expiry. It verifies zero code exchanges on refusal or lost acknowledgement,
  successful late acknowledgement, and idempotent custody recovery.
- Negative compiler fixtures reject the old Option conditions and Boolean
  results. Ordinary login, advanced configuration and native application types
  remain covered by the existing consumer.

## Script email evidence

The local issuer can model absent or unverified contact evidence without bypassing
login verification or constructing a verified identity:

```gleam
import gleam/option.{None, Some}
import warden/testing

let options =
  testing.provider_options()
  |> testing.with_email_claims(
    "ada",
    testing.EmailClaims(Some("ada@example.test"), Some(False)),
  )

// After starting the provider, omit both claims in future evidence.
testing.set_email_claims(provider, "ada", testing.EmailClaims(None, None))
```

An explicit override applies to that subject's new ID tokens and userinfo responses. Email
and verification are independently optional: None omits the JSON field rather
than emitting null, and Some(False) remains false. Unusual strings are preserved
so relying parties can test their own validation policy.

Subjects without an override retain the original defaults: subject-derived email
and verified true in ID tokens; subject-derived email with no verification field
in userinfo. Runtime updates do not alter already signed tokens or immutable
verified identities, and do not change the subject's stable identity key. This
API does not override reserved protocol claims or grant application permission.
The ordinary explicit local-provider trust and lifetime rules still apply.

## Provider and oracle suites

```sh
scripts/keycloak up
WARDEN_SUITE=keycloak gleam test
scripts/node-provider up
WARDEN_SUITE=node gleam test
scripts/interop up
WARDEN_SUITE=interop gleam test
scripts/browser-journey
scripts/conformance-suite up
scripts/conformance
```

- These commands operate disposable local providers. The scripts generate the test PKI in `build/test-pki`; browser journey needs Keycloak and local Chrome. Use the paired provider scripts' `down` command to stop fixtures after a run. No public demo issuer or production tenant is needed.
- Node provider and Hydra consent startup refuse an occupied port or existing ownership record. Their `down` commands request shutdown over a private control socket; old PID files are ignored. `provider-check` uses a fresh invocation token so failed startup cannot stop another invocation's Node fixture. Malformed or unreachable control records fail without signaling a process. After an uncatchable fixture death, inspect the corresponding `build/node-provider.owner` or `build/hydra-consent.owner` directory and remove that stale directory manually before restarting; do not kill a process based on an old PID file.
- Keycloak covers browser login, races, rotating refresh and revoked sessions. The node provider supplies forged/changed claim and transport cases and compares Warden with test-only `oidcc` 3.9.0. Dex and Hydra establish their particular interoperability contracts.
- The OpenID RP harness drives selected Basic, Config, Form Post, refresh, RP-initiated logout and third-party initiation plans from the retained `release-v5.3.1` fixture. Local pass receipts are regression evidence. Skipped, review-needed and interrupted modules remain distinct; certification requires an exact-release submission.
- Pin oracle identity and fixture revisions when recording a result. `oidcc`/Erlang jose are test-only, while runtime JOSE is gose/kryptos and HTTPS is HTTP Gun. The [supply-chain record](SUPPLY-CHAIN.md) preserves the tag, checksum, license and advisory-query limits.

## Evidence interpretation

- Preserve raw [conformance receipts](evidence/conformance/README.md), [HTTP Gun adoption logs](evidence/http-gun-adoption/README.md) and browser-journey JSON when updating an interpretation. Historical oidcc-backed receipts are under the evidence history directories.
- Read [oracle/evidence ADR](adr/0008-oracles-and-evidence-limits.md) for stricter-audience, required-ID-token, refresh and local-suite differences. A matching differential is bounded to its case and revision; it does not prove arbitrary provider compatibility or cryptographic safety.
- Races, unknown store effects, provider uncertainty, expiry barriers, process replacement, redaction and mailbox/resource checks need runtime evidence beyond opaque-type compilation. Native design Pending updates name unresolved authority or evidence gaps without turning report history into current failure claims.
- Release acceptance includes changed dependency/advisory review, the selected independent suites, supported-provider checks, release SBOM and independent review of Warden-owned security code. No retained report constitutes a certification or a release approval.

## CI checks and evidence

- The mandatory CI workflow runs the canonical local gate on pull requests and pushes to `master`. Its final CI status rejects failed, cancelled or skipped mandatory jobs. Provider evidence runs on relevant source, fixture, toolchain and sibling-pin changes, daily, and on request.
- CI checks out Warden beside public Sinal, HTTP Gun, Relay and JSON Blueprint at the full revisions in `sibling-revisions.txt`. Checkouts use the ordinary workflow token with read-only repository permissions and do not persist credentials. Fork pull requests run the same verification jobs.
- CI caches Hex package archives and compiler-produced path dependency fingerprints. It does not cache compiled output. Dependency preparation retries explicit Hex rate limits at most three times; other dependency failures stop the gate. Compiler and test failures are not retried.

| Obligation and authority                                                        | Reproducible command                                                                                     | Cadence and owner                          | Enforcement and retained evidence                                                          |
| ------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------ | ------------------------------------------------------------------------------------------ |
| Authored formatting; agent tooling instructions                                 | `nix flake check`                                                                                        | Local gate / mandatory CI                  | Mechanism; formatter diagnostics                                                           |
| Workflow, POSIX shell and JavaScript syntax                                     | `scripts/scriptlint`                                                                                     | Local gate / mandatory CI                  | Partial static correctness; actionlint, ShellCheck and Node diagnostics                    |
| Gleam build and authored Erlang warnings; Testing and retained capability scope | [Root build sequence](#fresh-root-builds-on-otp-29); unflagged consumer build and `scripts/erlang-check` | Local gate / mandatory CI                  | Mechanism for compiler diagnostics; warning rejection control                              |
| Native attacks, races, redaction and lifecycle; threat/authority coverage       | `WARDEN_SUITE=fast gleam test`                                                                           | Local gate / mandatory CI                  | Bounded runtime evidence; nonempty known suite selection                                   |
| Opaque constructors and public composition; test/extension ports                | `scripts/negative`, consumer build/tests, `scripts/relay-recipe`                                         | Local gate / mandatory CI                  | Compiler rejection plus positive control; public runtime and documentation recipe equality |
| Gate refusal semantics                                                          | `scripts/gate-regressions` and suite-runner EUnit tests                                                  | Local gate / mandatory CI                  | Mechanism; warnings, malformed/empty outcomes, exact known non-pass policy                 |
| Native design integrity; agent design-gate instructions                         | `nix run .#design-gate-check -- docs/design .`                                                           | Local gate / mandatory CI                  | Mechanism for freshness, vocabulary and layer integrity                                    |
| Independent providers; evidence/release conditions                              | `scripts/provider-check node`, `keycloak`, `interop`, `browser`                                          | Relevant changes / daily / full local gate | Bounded interoperability and browser evidence; logs and browser JSON                       |
| Selected OpenID plans; ADR 0008                                                 | `WARDEN_CONFORMANCE_POLICY=regression scripts/conformance-check basic,formpost,config,refresh,logout`    | Manual OpenID workflow / release selection | Bounded regression evidence; raw module logs and explicit acceptance summary               |
| Cache/resource costs; ADR 0007                                                  | `scripts/benchmark`                                                                                      | Optional manual benchmark workflow         | Observations only; environment and measurements, no latency threshold                      |

- Nix pins all tooling through `flake.lock`. The formatter excludes frozen evidence receipts, vendored upstream Compose/oracle records, deliberate negative compiler fixtures and generated output. Erlang warning checks compile authored helpers with `erlc -Werror` after Gleam resolves their dependencies; generated and upstream Erlang retain their own owners. Fault-test runtime reports are not parsed as compiler warnings.
- OpenID verdicts default to strict: every selected module must finish PASSED. Regression mode permits only the exact SKIPPED unsigned-token and REVIEW logout outcomes in `test/conformance/known-outcomes.json`; these remain non-pass evidence. Third-party interruption, unknown outcomes, driver errors, missing modules, malformed evidence and empty selections fail both policies. The manual workflow defaults to the five retained regression plans; thirdparty is selectable and retains its unresolved independent evidence. Neither policy confers certification.
- The driver archives a terminal or unready setup status and its module log before starting the reference RP. This preserves the oracle's original outcome when startup would otherwise obscure it. The gate exercises the actual driver against a disposable HTTPS oracle API fixture with no RP build, including setup timeout and a ready-module control. Port 8443 must be unused for this check; stop the local conformance fixture before running the gate. Fixture results verify the driver only, not OIDC interoperability.
- Fixture lifecycle regressions exercise real test-owned processes and local sockets: unrelated-listener survival, occupied-port refusal, normal/repeated shutdown, stale PID files, different invocation tokens, failed/interrupted startup, malformed/unreachable state and server-side token refusal. Port 19443 must be unused before running this regression. These checks establish test-tooling ownership, not relying-party protocol behavior.
- Each workflow retains bounded artifacts with package/sibling revisions and logs; provider jobs retain image and browser identities. Artifacts exclude generated PKI/private keys. Raw checked-in history is never overwritten by a run. Dependency/advisory review, release SBOM, independent security review and unresolved native Pending updates remain separate obligations.

## Optional PostgreSQL integration

The canonical gate runs `scripts/postgres-check`, which owns a temporary local
PostgreSQL cluster. `integrations/warden_postgres/test` exercises the public
store adapter and Warden clients, independently of any application. PostgreSQL
is a development dependency and is not added to the core Warden package.
The same check runs `scripts/postgres-negative` from a separate consumer package:
the adapter's opaque configuration constructor must be inaccessible, and the
public construction path must compile. Database tests exercise schema and timeout
settings through the public setters alongside storage and recovery behavior.
