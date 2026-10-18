# Mandatory CI runs the canonical local gate against pinned sibling revisions

<a id="adr-0015"></a>

- **Decision:** the mandatory CI workflow runs the same `scripts/check` gate a developer runs locally, on pull requests and pushes to `master`. It checks out Warden beside public Sinal, HTTP Gun, Relay and JSON Blueprint at the full revisions listed in `sibling-revisions.txt`. Provider evidence runs separately on relevant source, fixture, toolchain and sibling-pin changes, daily, and on request.
- **Need:** Warden declares unpublished sibling packages through immutable Git sources and builds consumers that depend on sibling checkouts by path. A moving sibling branch would make a failing gate irreproducible, and a CI-only command set would let local and CI results diverge.
- **Alternatives:** tracking sibling branches gives early integration signal but no reproducible result. Vendoring siblings duplicates their source and design layers. A separate CI command list drifts from the local gate.
- **Consequences:** a sibling change reaches Warden only through an explicit pin update that passes the gate. Checkouts use the ordinary workflow token with read-only permissions and persist no credentials, so fork pull requests run the same verification. CI caches Hex archives and path-dependency fingerprints but no compiled output. Dependency preparation retries explicit Hex rate limits at most three times, and compiler and test failures are never retried.
- **Evidence limits:** CI status evidences the gate at the pinned revisions. It does not qualify other sibling revisions, provider interoperability or release certification.
