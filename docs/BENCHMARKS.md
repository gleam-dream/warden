# Warden benchmarks

These local measurements were recorded on 2026-10-05. They describe the provider
fetch-ownership change on one machine; they were not rerun for this documentation
cleanup and are not deployment capacity guarantees.

The immutable [measurement receipt](https://github.com/gleam-dream/warden/blob/f3847d102c0db9f66e4d4a72a9c7b3028507c7ac/docs/PROGRESS.md#round-9-provider-fetch-ownership-2026-10-05)
records the numbers and method. [ADR 0007](adr/0007-cache-incarnation-ownership.md)
explains the ownership requirement and allocation cost. The receipt names
baseline revision `99531f3`; its own revision is
`f3847d102c0db9f66e4d4a72a9c7b3028507c7ac`. It does not identify the exact measured
after revision separately.

## Token validation, key refresh and cached reads

The runtime was OTP 28 with four online schedulers and no concurrent stress gate.
The CPU, RAM, operating system and exact OTP patch version were not recorded.

| Workload                                         |              Before |               After | Aggregation                                               |
| ------------------------------------------------ | ------------------: | ------------------: | --------------------------------------------------------- |
| One client validating a cached JWT               | 2,568 validations/s | 2,528 validations/s | Median of three warmed runs; 3,000 validations/run        |
| Four clients validating cached JWTs concurrently | 9,761 validations/s | 9,737 validations/s | Median of three warmed runs; 3,000 validations/client/run |
| 100 sequential TLS signing-key refreshes         |             5.232 s |             5.223 s | Median of three warmed runs                               |
| One cache, sequential snapshot reads             |      20.259 µs/read |      20.230 µs/read | Median of five alternating pairs; 20,000 reads/cache/run  |
| Four caches, interleaved snapshot reads          |      20.581 µs/read |      20.798 µs/read | Median of five alternating pairs; 20,000 reads/cache/run  |

These values come from the [recorded comparison](https://github.com/gleam-dream/warden/blob/f3847d102c0db9f66e4d4a72a9c7b3028507c7ac/docs/PROGRESS.md#round-9-provider-fetch-ownership-2026-10-05).
Token-validation and refresh ranges overlapped. Snapshot runs used 1,000 warmup
reads per cache in the same VM, loading baseline and changed provider BEAM code
between fully stopped fixtures. The one-cache ranges were 17.057–20.337 µs/read
before and 19.898–20.346 after. Four-cache ranges were 20.324–20.759 before and
20.587–21.617 after.

After explicit garbage collection, cache memory was 5,768–8,784 bytes in both
sets of paired samples. Heap allocation bins varied; the observations do not
establish a memory improvement. Idle and completed-burst caches had no active
lifecycle monitors or queued messages.

## Large signing-key sets

A separate [five-pair forwarding measurement](https://github.com/gleam-dream/warden/blob/f3847d102c0db9f66e4d4a72a9c7b3028507c7ac/docs/PROGRESS.md#large-key-set-forwarding-measurement)
compared a monitored direct worker with the real fetch guardian on OTP 28 with
four schedulers. Each pair alternated order and used generated public P-256 keys
with distinct identifiers. Worker-owned terms avoided literal-sharing shortcuts.
The following medians include decoding a serialized term and delivering it:

| Keys  | Direct worker |     Guardian | Additional time |
| ----- | ------------: | -----------: | --------------: |
| 1     |       7.46 µs |     14.18 µs |         6.72 µs |
| 100   |     244.30 µs |    296.16 µs |        51.86 µs |
| 1,000 |   2,448.96 µs |  3,003.75 µs |       554.79 µs |
| 5,000 |  14,815.49 µs | 19,364.45 µs |     4,548.96 µs |

The 5,000-key fixture was 828,903 JSON bytes, below the 1 MiB response limit, but
its decoded flat term was 2,160,024 bytes. A guardian paused before forwarding
occupied 2,546,568 bytes after garbage collection. That excludes worker, cache
and transport memory and is not peak memory.

For the actual JWKS parsing-and-delivery workload at 5,000 keys, medians were
1.435 s direct and 1.410 s guarded. The ranges overlapped: 1.412–1.778 s direct
and 1.395–1.691 s guarded. Parsing dominated; these samples do not show a
speedup. The comparison isolates worker delivery, not two complete Warden
releases. See the [receipt](https://github.com/gleam-dream/warden/blob/f3847d102c0db9f66e4d4a72a9c7b3028507c7ac/docs/PROGRESS.md#large-key-set-forwarding-measurement)
for the recorded method. Its standalone synthetic harness, iterations per pair
and hardware details were not retained in this checkout.

## Run the retained benchmark entry points

From the Warden repository, open an Erlang shell with four schedulers:

```sh
ERL_FLAGS="+S 4" nix develop -c gleam shell
```

Then run:

```erlang
warden_fetch_ownership_test:benchmark().
warden_fetch_ownership_test:snapshot_benchmark().
```

The [retained source](../test/warden_fetch_ownership_test.erl) creates its own
local HTTPS test provider and stops each client fixture. `benchmark/0` warms
100 validations per client, measures 3,000 per client for one and four clients,
reports throughput and latency percentiles, and measures 100 sequential key
refreshes. `snapshot_benchmark/0` warms 1,000 reads per cache and measures 20,000
per cache for one and four caches.

These commands produce new samples for the current checkout. They do not recreate
the historical baseline comparison or the separate large-key-set experiment.
Repeat runs and retain their raw output, source/dependency revisions and machine
configuration when reporting a new result. Neither benchmark is a correctness-gate
performance threshold.
