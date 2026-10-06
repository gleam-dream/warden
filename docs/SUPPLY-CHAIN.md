# Dependency provenance and release checks

`gleam.toml` owns admitted dependency ranges. `manifest.toml` records a concrete
resolution; it does not qualify every version admitted by those ranges. The
[transport decision](adr/0002-bounded-provider-transport.md) explains runtime
ranges, sibling paths and the requirement to renew behavioral evidence after
resolution changes. [ADR 0008](adr/0008-oracles-and-evidence-limits.md) owns the
dated dependency/advisory observations and their limits.

## Retained sources

| Scope                             | Authority and retained evidence                                                                                                      |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Runtime cryptography              | Public gose and kryptos APIs; exact resolution/checksums in `manifest.toml`; recorded license and source attribution in ADR 0008     |
| HTTP and observations             | HTTP Gun and Sinal sibling declarations; their manifests, licenses and package-local design layers                                   |
| Erlang/Gleam runtime dependencies | Package declarations and resolution manifest; licenses supplied with their exact sources                                             |
| Differential oracle               | Exact oidcc test-only pin; Apache-2.0 record declarations in `test/integration/oidcc_records.hrl`; source/tag provenance in ADR 0008 |
| Scripted provider signing         | Exact erlang-jose test-only pin; provider fixture lockfiles and notices                                                              |
| Independent providers             | Keycloak image digest, node-provider package locks, OIDF compose image pins and retained test harnesses                              |
| Raw qualification receipts        | `docs/evidence/` and the commands in [TESTING.md](TESTING.md); historical interpretation in ADRs                                     |

## Qualify a release

- Record the actual package, sibling, dependency, fixture and toolchain revisions.
  Replace unpublished sibling path dependencies with their approved release
  declarations before publication.
- Review the resolved upstream changelogs, licenses and security advisories;
  produce the release SBOM. Check advisory-query coverage against known controls.
  An empty query result does not establish absence of vulnerabilities.
- Run the selected provider, conformance and compatibility suites when their
  relevant dependencies change. Keep failed, skipped and human-review results
  distinct from passed assertions.
- Keep runtime and test-only dependencies separate. oidcc, erlang-jose and
  telemetry_registry are development oracles and are not installed by an
  application merely because it uses Warden.
- Preserve fixture licenses and exact source attribution when refreshing inputs.
  A new resolution or fixture pin needs its own evidence; an older receipt cannot
  qualify it.
