# Round 9 migration

## Provider fetch ownership

- No application code changes are required. `warden.new`, `start`,
  `supervised`, `stop`, configuration and resource validation keep their
  signatures and error types.
- Before: a fetch sent its completion to the cache's registered name. It
  could outlive that cache and replace a restarted cache's fresh keys with
  an older key set.
- After: a fetch targets one cache process. A short-lived guardian monitors
  that cache and owns the network worker. Old completions and monitor
  notifications cannot settle a newer fetch.
- Before: a killed worker could leave key-refresh callers waiting until
  their timeout and leave the cache permanently marked busy.
- After: the cache observes worker loss through its guardian. Key callers
  receive the existing last-snapshot/failure result; discovery and metadata
  reload use their existing retry or reload cadence.
- Cached reads remain asynchronous. Successful fetches add no provider
  request. Recovery after a lost worker resumes the existing bounded retry
  cadence; a restarted cache discards old work and may fetch again. There is
  no new retry policy, timeout, global coordinator or dependency.
- `stop` still requests supervisor shutdown and waits up to five seconds
  for exit. Returning after that bound does not prove shutdown. Worker
  termination follows the cache's exit notification, independently of provider
  response or telemetry-handler progress. This is not a synchronous join
  of every worker before `stop` returns.

## Whole-tree restart

- Before: a hard-killed client supervisor could disappear before its named
  children did. Immediate replacement then failed on registered names and
  exhausted the parent supervisor's restart budget.
- After: startup monitors the actual previous pool, provider, sweeper and
  optional Warden-owned store processes, then starts replacements after those
  processes exit. External stores are not joined. A live client supervisor
  still returns `AlreadyStarted`.
- `config.with_startup_timeout` keeps its signature and default. Manual startup
  shares one deadline between discovery, first keys and previous-process
  cleanup. Supervised startup uses that bound for cleanup; background discovery
  retains its independent retry cadence. Expiry is the existing
  `StartupTimedOut`, whose description now includes cleanup.
- No names are taken over, restart tolerance is unchanged, and no sleep or
  polling loop is added to production. Cleanup adds at most five temporary
  monitors during startup, removed on success or expiry. Steady cached reads
  and provider fetches do not use this path.
- The supervised startup callback waits synchronously. A held old child can
  delay that parent supervisor's management and restart handling up to the
  configured startup bound (15 s by default). Other running clients' request
  actors remain independent.

## Lifecycle validation

- Four regressions failed against unchanged production code before the fix:
  stale key restoration through the public resource validator, cache exit,
  client shutdown, and a lost refresh worker. The compatible cached-read
  regression already passed.
- Nineteen focused tests cover those paths plus normal process exits,
  guardian failure, discovery and reload recovery, stalled HTTP, direct
  `warden.stop`, queued completion after shutdown, old completion and monitor
  replay, independent clients,
  bookkeeping after a refresh burst, held child registration across tree
  restart and bounded startup expiry.
- Scheduling barriers use real local HTTPS, telemetry and process monitors.
  Key-rotation assertions validate application-visible tokens and refreshed
  key snapshots. No external provider credentials are used.

## Resource cost

- An idle cache adds no process or monitor. Its selector includes a
  process-specific completion channel and monitor-message handling.
- An active fetch adds one guardian beside the existing network worker,
  three lifecycle monitors and one link. The guardian forwards one result,
  adding a message hop and copying that term once more. Copy cost grows with
  the decoded key-set size; the small local benchmark does not measure the
  worst-case cost of a large JWKS within the existing response-size bound.
- Helpers and monitors terminate when the operation or owner ends. They are
  local to a cache, with at most one active fetch per cache. Cached reads
  and unrelated clients do not acquire a shared lock.
- Local before/after measurements are recorded in `docs/PROGRESS.md`.
  They measure a microbenchmark on one machine, not deployment capacity.
