# Benchmarks are retained as local observations without correctness thresholds

<a id="adr-0017"></a>

- **Decision:** `docs/BENCHMARKS.md` retains local measurements of provider cache cost and fetch ownership, and links to `docs/ORACLE.md`, which holds the independent references run on the same provider fixtures. The entry points `warden_fetch_ownership_test:benchmark/0` and `snapshot_benchmark/0` produce new samples. No benchmark result gates correctness or release.
- **Need:** the fetch-ownership design adds one process, three monitors, one link and one forwarding hop per active fetch. Reviewers need the measured cost of that choice, and operators need to know what the numbers do and do not promise.
- **Alternatives:** a latency or throughput threshold in the gate would fail on unrelated hardware differences and invite tuning to the test. Omitting measurements would leave the ownership cost undocumented.
- **Findings:** the recorded medians were 2,528 token validations per second for one client and 9,737 across four concurrent clients, from three warmed runs on OTP 28 with four schedulers on 2026-10-05. A 5,000-key JWKS parse-and-deliver comparison showed overlapping direct and guarded ranges, so it shows no speedup and no measurable forwarding cost. Parsing dominated.
- **Evidence limits:** the measurements come from one machine, lack hardware provenance, and do not identify the measured baseline revision separately from the receipt revision. They are not deployment capacity guarantees. A new result retains its raw output, source and dependency revisions and machine configuration.
- **Related:** [ADR 0007](0007-cache-incarnation-ownership.md) owns the ownership requirement and allocation cost.
