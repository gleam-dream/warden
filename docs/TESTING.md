# Testing Warden

## Local checks

- Run `nix develop -c scripts/check` for formatting, warnings-as-errors build, the fast suite, negative compilation fixtures, the public consumer and the compiled Relay recipe. The fast gate needs no provider container or external issuer.
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
