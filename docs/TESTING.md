# Testing Warden

## Local checks

- Run `nix develop -c scripts/check` for the complete local gate below. It requires the pinned sibling layout but no provider container or external issuer. Run `nix develop -c scripts/check full` to additionally execute all four disposable provider/browser suites. Full requires Docker Compose and installed Google Chrome.
- Run `nix run .#design-gate-render -- docs/design docs/design/design-layer.pdf`, then `nix run .#design-gate-check -- docs/design .` after editing design sources or ADRs. Estimate context with `nix run .#design-gate-context -- docs/design --estimate`; use the manifest and digest to select a section.
- Use `warden/testing` for explicitly trusted local HTTPS issuer scripts and `testing.check_store` for the general CAS port. Deployment adapters still require database-specific lock, crash, durability and rollback tests.

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
- Keycloak covers browser login, races, rotating refresh and revoked sessions. The node provider supplies forged/changed claim and transport cases and compares Warden with test-only `oidcc` 3.9.0. Dex and Hydra establish their particular interoperability contracts.
- The OpenID RP harness drives selected Basic, Config, Form Post, refresh, RP-initiated logout and third-party initiation plans from the retained `release-v5.3.1` fixture. Local pass receipts are regression evidence. Skipped, review-needed and interrupted modules remain distinct; certification requires an exact-release submission.
- Pin oracle identity and fixture revisions when recording a result. `oidcc`/Erlang jose are test-only, while runtime JOSE is gose/kryptos and HTTPS is HTTP Gun. The [supply-chain record](SUPPLY-CHAIN.md) preserves the tag, checksum, license and advisory-query limits.

## Evidence interpretation

- Preserve raw [conformance receipts](evidence/conformance/README.md), [HTTP Gun adoption logs](evidence/http-gun-adoption/README.md) and browser-journey JSON when updating an interpretation. Historical oidcc-backed receipts are under the evidence history directories.
- Read [oracle/evidence ADR](adr/0008-oracles-and-evidence-limits.md) for stricter-audience, required-ID-token, refresh and local-suite differences. A matching differential is bounded to its case and revision; it does not prove arbitrary provider compatibility or cryptographic safety.
- Races, unknown store effects, provider uncertainty, expiry barriers, process replacement, redaction and mailbox/resource checks need runtime evidence beyond opaque-type compilation. Native design Pending updates name unresolved authority or evidence gaps without turning report history into current failure claims.
- Release acceptance includes changed dependency/advisory review, the selected independent suites, supported-provider checks, release SBOM and independent review of Warden-owned security code. No retained report constitutes a certification or a release approval.

## CI checks and evidence

- The mandatory CI workflow runs the canonical local gate on every push and pull request. Its final CI status rejects failed, cancelled or skipped mandatory jobs. Provider evidence runs on relevant source, fixture, toolchain and sibling-pin changes, daily, and on request.
- CI checks out Warden beside public Sinal, HTTP Gun, Relay and JSON Blueprint at the full revisions in `sibling-revisions.txt`. Checkouts use the ordinary workflow token with read-only repository permissions and do not persist credentials. Fork pull requests run the same verification jobs.

| Obligation and authority                                                        | Reproducible command                                                                                  | Cadence and owner                          | Enforcement and retained evidence                                                          |
| ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------ | ------------------------------------------------------------------------------------------ |
| Authored formatting; agent tooling instructions                                 | `nix flake check`                                                                                     | Local gate / mandatory CI                  | Mechanism; formatter diagnostics                                                           |
| Workflow, POSIX shell and JavaScript syntax                                     | `scripts/scriptlint`                                                                                  | Local gate / mandatory CI                  | Partial static correctness; actionlint, ShellCheck and Node diagnostics                    |
| Gleam build and authored Erlang warnings; Testing and retained capability scope | `gleam build --warnings-as-errors`, `scripts/erlang-check` in root and consumer                       | Local gate / mandatory CI                  | Mechanism for compiler diagnostics; warning rejection control                              |
| Native attacks, races, redaction and lifecycle; threat/authority coverage       | `WARDEN_SUITE=fast gleam test`                                                                        | Local gate / mandatory CI                  | Bounded runtime evidence; nonempty known suite selection                                   |
| Opaque constructors and public composition; test/extension ports                | `scripts/negative`, consumer build/tests, `scripts/relay-recipe`                                      | Local gate / mandatory CI                  | Compiler rejection plus positive control; public runtime and documentation recipe equality |
| Gate refusal semantics                                                          | `scripts/gate-regressions` and suite-runner EUnit tests                                               | Local gate / mandatory CI                  | Mechanism; warnings, malformed/empty outcomes, exact known non-pass policy                 |
| Native design integrity; agent design-gate instructions                         | `nix run .#design-gate-check -- docs/design .`                                                        | Local gate / mandatory CI                  | Mechanism for freshness, vocabulary and layer integrity                                    |
| Independent providers; evidence/release conditions                              | `scripts/provider-check node`, `keycloak`, `interop`, `browser`                                       | Relevant changes / daily / full local gate | Bounded interoperability and browser evidence; logs and browser JSON                       |
| Selected OpenID plans; ADR 0008                                                 | `WARDEN_CONFORMANCE_POLICY=regression scripts/conformance-check basic,formpost,config,refresh,logout` | Manual OpenID workflow / release selection | Bounded regression evidence; raw module logs and explicit acceptance summary               |
| Cache/resource costs; ADR 0007                                                  | `scripts/benchmark`                                                                                   | Optional manual benchmark workflow         | Observations only; environment and measurements, no latency threshold                      |

- Nix pins all tooling through `flake.lock`. The formatter excludes frozen evidence receipts, vendored upstream Compose/oracle records, deliberate negative compiler fixtures and generated output. Erlang warning checks compile authored helpers with `erlc -Werror` after Gleam resolves their dependencies; generated and upstream Erlang retain their own owners. Fault-test runtime reports are not parsed as compiler warnings.
- OpenID verdicts default to strict: every selected module must finish PASSED. Regression mode permits only the exact SKIPPED unsigned-token and REVIEW logout outcomes in `test/conformance/known-outcomes.json`; these remain non-pass evidence. Third-party interruption, unknown outcomes, driver errors, missing modules, malformed evidence and empty selections fail both policies. The manual workflow defaults to the five retained regression plans; thirdparty is selectable and retains its unresolved independent evidence. Neither policy confers certification.
- Each workflow retains bounded artifacts with package/sibling revisions and logs; provider jobs retain image and browser identities. Artifacts exclude generated PKI/private keys. Raw checked-in history is never overwritten by a run. Dependency/advisory review, release SBOM, independent security review and unresolved native Pending updates remain separate obligations.
