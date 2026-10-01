# HTTP Gun adoption validation (2026-10-01)

> **Outcome (2026-10-01): adopted.** The owner accepted the five rows (D17)
> and chose local path dependencies until publication (D16); Warden's
> transport now runs on HTTP Gun (D11). The experimental adapter, probes and
> reproduction script were superseded by `src/warden/internal/transport.gleam`,
> `test/warden/transport_test.gleam` and `test/warden/transport_pool_test.gleam`
> and removed. The report below records the validation as it stood before
> that decision.

**Not adopted.** Warden production code still uses its owned transport
(`src/warden/internal/transport.gleam`). Everything below ran in disposable
copies; HTTP Gun, Sinal and oversight were only read.

Current revision: HTTP Gun `369da4f` ("address Warden trust and connection
reuse gaps"). The first run, against `b517725`, is summarised under
[History](#history).

| Adoption gate (decision D11)                             | Status                                                                                                                                                                                                                                                                                        |
| -------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A released HTTP Gun version contains the feature         | **Not met.** Hex has no `http_gun` package (`https://hex.pm/api/packages/http_gun` → 404); `369da4f` has no tag and is not on `origin`; `gleam.toml` says 0.1.0.                                                                                                                              |
| Warden's transport tests pass unchanged through HTTP Gun | **Not met.** 17 of 19 pass; 2 table tests differ on 5 rows. 4 rows are rejected with a coarser class (a dependency limit HTTP Gun documents) and 1 row is the owner-accepted reason-phrase case. Meeting this gate now needs an owner decision on those expectations, not more HTTP Gun work. |

## Inputs and environment

| Input              | Revision                                                                                                      |
| ------------------ | ------------------------------------------------------------------------------------------------------------- |
| Warden             | `230c6bb` plus one uncommitted test fix found here (`test/integration/node/node_raw_ffi.erl`)                 |
| HTTP Gun           | `369da4ffc2671c1dbc63e1ecd1355e8ca42e403e`, unmodified                                                        |
| Sinal              | `8acec4507f23daa7f49c40cc7d39816a5a4c3d1d` (HTTP Gun's pinned snapshot)                                       |
| Warden toolchain   | Warden's nix shell: Gleam 1.18.1, OTP 28, Darwin ARM64                                                        |
| HTTP Gun toolchain | HTTP Gun's `dev/env`: Gleam 1.18.1, OTP 29                                                                    |
| Providers          | Keycloak 26.7.5, node-oidc-provider 9.12.2, Dex v2.45.1, Ory Hydra v26.2.0, all local, disposable credentials |

Reproduce: `docs/evidence/http-gun-adoption/run-experiment.sh NEW_DIR`
(copies by `git archive`, builds only in `NEW_DIR`; provider suites need
the providers running from the real checkout). The adapter and probes are in
[`experiment/`](experiment/); outputs in [`logs/`](logs/).

### Executed here vs inherited

Executed here, against `369da4f`: HTTP Gun's own suite (128 tests, its
toolchain, gleam_stdlib 1.0.5), the G2 compile probe, Warden's transport
tests unchanged, the per-row framing table, nine security probes, Warden's
fast suite, negative compile cases, the public consumer, and the Keycloak,
node-oidc-provider and Dex/Hydra suites, all through the adapter.
Inherited from HTTP Gun's receipts and **not** re-run: OTP 27/29 matrices,
H2/nghttpd interoperability, large blocked uploads, recording/load checks,
LLM Wire downstream results. They say nothing about Warden compatibility.

## The experimental adapter

`experiment/transport.gleam` keeps Warden's transport interface (types,
`policy`, `send`, `classify`, `class_name`, `authority`, `max_request_body`,
`monotonic_ms`) so tests run unchanged, and removes Warden's own DNS, TLS,
socket and parser code. Networking uses only HTTP Gun's public API; trust
anchors go in memory (`config.Anchors`).

- Application policy kept in the adapter: HTTPS only; URL shape (userinfo,
  fragment, port); request-header hygiene; 64 KiB request bodies; refusal of
  any non-identity `content-encoding`; **refusal of a declared
  `content-length` above the limit before reading** (HTTP Gun alone waits
  out the deadline: `DeclaredOversize` → `DeadlineExceeded`); failure mapping;
  observations.
- Delegated to HTTP Gun: destination policy and pinned DNS, TLS, framing,
  header and body limits, the deadline, connection readiness, submission
  evidence, mailbox hygiene.
- **Experiment only:** one HTTP Gun client per request. The shared-client
  design is exercised by the security probes.

### Failure mapping

Evidence decides the stage: `NotSubmitted` → `NotSent`, `MayHaveBeenSent` →
`Sent`. Neither proves remote execution.

| HTTP Gun reason                                            | Warden class         |
| ---------------------------------------------------------- | -------------------- |
| `DestinationRejected` / `ResolutionFailed`                 | same                 |
| `…(ConnectionRefused)`                                     | `ConnectionRefused`  |
| `…(CertificateRejected                                     | TlsFailed)`          | `TlsRejected`       |
| `…(TransportTimeout)`, `DeadlineExceeded`, `ReadTimeout`   | `Timeout`            |
| `…(HeaderLimitReached)`                                    | `HeadersTooLarge`    |
| `…(ProtocolError                                           | UnexpectedProtocol)` | `MalformedResponse` |
| `…(PeerClosed                                              | ConnectionReset      | PeerDraining        | UnknownTransport)` | `ConnectionFailed` (not sent) / `ReceiveFailed` (sent) |
| `LimitExceeded(Request*)`, `InvalidRequest`                | `InvalidRequest`     |
| `LimitExceeded(ResponseHeader*)`                           | `HeadersTooLarge`    |
| `LimitExceeded(ResponseChunk*/Queue*/CollectedBody*)`      | `BodyTooLarge`       |
| admission, closed client, cancellation, ownership, fixture | `InternalError`      |

`PeerClosed` and `UnknownTransport` are deliberately not mapped to
`TruncatedBody` or `MalformedResponse`: HTTP Gun reports both a truncated body
and Gun's own rejection of a bad chunk size as `PeerClosed`, and invalid
status lines or signed lengths surface only as dependency crashes.

## Compatibility matrix: Warden transport tests, unchanged

All rows pass except the two tables ([log](logs/transport-tests-unchanged.log)):
verified TLS; loopback refused before connecting; wrong-host, self-signed and
expired certificates; the IP-literal certificate check (T1); system trust
refusing the test CA; redirects returned, not followed; chunked and interim
responses; the deadline; request shape; connection refused; destination
policy; single resolution; classification; the oidcc adapter test; the complete
header limit (T4); the request cap (T3); the IPv6 `authority` helper (T6, a
pure Warden helper; the probe below checks HTTP Gun's actual Host header).

Per-row outcomes of the two tables ([log](logs/framing-and-bounds-table.log)):

| Row                                                      | Expected                          | Through HTTP Gun                          | Assessment                                                                                   |
| -------------------------------------------------------- | --------------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------- |
| DeclaredOversize, EndlessChunked, CloseDelimitedOversize | `Sent BodyTooLarge`               | same                                      | match (first via the adapter's early check)                                                  |
| ManyHeaders, BigHeaderLine, HeaderOvershoot              | `Sent HeadersTooLarge`            | same                                      | match (ManyHeaders via `HeaderLimitReached`)                                                 |
| Gzip                                                     | `Sent UnsupportedContentEncoding` | same                                      | match (adapter check)                                                                        |
| ControlInHeader                                          | `Sent MalformedResponse`          | same                                      | match                                                                                        |
| Truncated                                                | `Sent TruncatedBody`              | `Sent ReceiveFailed` (`PeerClosed`)       | rejected, coarser class                                                                      |
| BadStatus                                                | `Sent MalformedResponse`          | `Sent ReceiveFailed` (`UnknownTransport`) | rejected, coarser class                                                                      |
| SignedContentLength                                      | `Sent MalformedResponse`          | `Sent ReceiveFailed` (`UnknownTransport`) | rejected, coarser class                                                                      |
| SignedChunkSize                                          | `Sent MalformedResponse`          | `Sent ReceiveFailed` (`PeerClosed`)       | rejected, coarser class                                                                      |
| BareLfHead                                               | `Sent MalformedResponse`          | **accepted**: 200, no headers, body `ok`  | owner-accepted reason-phrase limitation; with one request per connection nothing is smuggled |

Every rejected row stays a rejection with `Sent` evidence, so no security
property is lost. Warden's public `TransportReason` would report
`OtherTransportFailure` where it now reports `MalformedHttp` or
`TruncatedResponse` for those four rows.

## Security acceptance probes

From `experiment/gun_security_probe_test.gleam` and the transport tests
([log](logs/security-probes.log)). All nine probes pass.

| Requirement                                              | Evidence                                                                                                                                                                                                           | Result                                  |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------- |
| Default loopback refusal before connection               | transport test; server counts 0 requests                                                                                                                                                                           | pass                                    |
| Explicit loopback permission                             | every local test                                                                                                                                                                                                   | pass                                    |
| Private, mixed and metadata answers                      | transport test; `100.100.100.200` and `fd00:ec2::254` refused **with** `allow_private`                                                                                                                             | pass                                    |
| Single resolution, pinned connection                     | transport test (resolver called once)                                                                                                                                                                              | pass                                    |
| Reuse without re-resolution; replacement resolves again  | shared client: 2 requests → 1 resolution, 1 connection; after peer close → 2 and 2                                                                                                                                 | pass                                    |
| No admission onto closing connections                    | request 100 ms, 1 s and 3 s after a peer close: `Ok(200)` on a new connection; `connection: close` on every request: both `Ok(200)`, 2 connections                                                                 | pass                                    |
| Host allowlist (checked before DNS)                      | transport test; HTTP Gun source order                                                                                                                                                                              | pass                                    |
| Mapped / NAT64 / Teredo / ORCHID / documentation classes | classification table                                                                                                                                                                                               | pass                                    |
| Hostname and IP certificates                             | transport tests                                                                                                                                                                                                    | pass                                    |
| Stalled send                                             | 64 KiB POST to a peer that never reads → `Sent Timeout` at 501–504 ms (deadline 500). Warden's cap fits socket buffers, so the stall is in the response wait; HTTP Gun's 16 MiB blocked-upload tests are inherited | pass                                    |
| Caller death on a shared client                          | killed caller; client keeps serving; `Stats(0, 0, 0)`                                                                                                                                                              | pass                                    |
| Bounded shutdown                                         | `stop` returned in 0 ms; in-flight request `Closed, MayHaveBeenSent`                                                                                                                                               | pass                                    |
| Clean long-lived caller mailbox                          | after adapter and shared-client timeouts and the late server reply: 0 → 0                                                                                                                                          | pass                                    |
| Complete header limits                                   | HeaderOvershoot, BigHeaderLine, ManyHeaders                                                                                                                                                                        | pass                                    |
| IPv6 authority                                           | `host: [::1]:PORT` on a non-default port; `[::1]:443` cannot be bound here (`eacces`), so the default-port form is **not probed**                                                                                  | partial                                 |
| Framing rejection                                        | per-row table                                                                                                                                                                                                      | 4 rows coarser, 1 accepted (documented) |
| Conservative submission evidence                         | post-connect failures `MayHaveBeenSent`; refusals `NotSubmitted`                                                                                                                                                   | pass                                    |
| Redirects as data, no retries, no decompression          | redirect test (one request); Gzip passed through, refused by the adapter                                                                                                                                           | pass                                    |

## Warden gates through the adapter

| Gate                                        | Result                                                                                                                                                       |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `gleam build --warnings-as-errors`, format  | pass                                                                                                                                                         |
| Fast suite                                  | 124 of 126 pass: only the two transport tables fail; every login, refresh, session, redaction, observation and store test passes over HTTPS through HTTP Gun |
| Negative compile cases                      | 13 + positive control pass                                                                                                                                   |
| Public consumer package (`consumer/`)       | builds with warnings as errors; 8 tests pass                                                                                                                 |
| Keycloak / node-oidc-provider / Dex + Hydra | 15 / 7 / 2 pass (Keycloak rerun after a transient Hex API failure in the scripted step)                                                                      |

Browser journey and OIDF conformance were not run through the adapter: they
start the reference app from the real checkout.

## Dependency gaps

| Gap                                      | Status at `369da4f`                                                                                                                                                                                                                      | Evidence                                                                      |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| G1 `gleam_stdlib < 1.0.0`                | **fixed** (`< 2.0.0`; no patch needed)                                                                                                                                                                                                   | Warden resolves HTTP Gun as committed                                         |
| G2 no in-memory trust anchors            | **fixed** (`config.Anchors(List(BitArray))`)                                                                                                                                                                                             | `experiment/g2_probe.gleam` compiles; the adapter uses it; all TLS tests pass |
| G3 admission onto closing connections    | **fixed** (H1 readiness check; `Connection: close` retires the lease)                                                                                                                                                                    | both G3 probes pass                                                           |
| G4 class precision                       | **partly fixed**: header-count limit → `HeaderLimitReached`. Invalid status, signed lengths, truncation and bad chunk sizes remain coarse; HTTP Gun documents them as dependency failures it will not reclassify without a parser change | per-row table                                                                 |
| G5 no early refusal of a declared length | adapter covers it; optional upstream                                                                                                                                                                                                     | `DeclaredOversize` direct row                                                 |

Not gaps: controls in the status reason phrase (owner-accepted), close-
delimited TLS truncation ambiguity (T5). **mTLS:** Warden has no
requirement (client authentication is public, basic, post, secret JWT or
private-key JWT; mTLS aliases disabled by decision D3).

## Owner decision needed for the second gate

Accept, for the transport tests after migration:

1. `Truncated`, `BadStatus`, `SignedContentLength`, `SignedChunkSize` →
   `Sent ReceiveFailed` (rejected; diagnostics coarser), and
2. `BareLfHead` → accepted as a close-delimited 200, matching the
   reason-phrase limitation already accepted for HTTP Gun,

or keep the current expectations, which blocks adoption until Gun/Cowlib
expose those distinctions. The release gate is independent and still needs a
published HTTP Gun (and Sinal).

## Warden defect found

`test/integration/node/node_raw_ffi.erl` still called
`warden_oidcc:classify/1`, deleted with the oidcc backend (D13). The node
suite passed in the real checkout only because a stale compiled
`warden_oidcc.beam` survived in `build/`; a clean build failed with `undef`.
Fixed in the working tree (uncommitted); four stale beams were removed from
the real `build/`. Gates should also run from a clean build.

## Migration proposal (once both gates are met)

1. **Dependencies:** `http_gun = "== x.y.z"` and `gleam_http`; no path
   dependencies (Sinal must be released too).
2. **Ownership:** one HTTP Gun client per Warden client as a supervised child
   (`http_gun.child(settings)`) started before the provider cache, settings
   derived from the validated configuration (immutable; a policy change
   means a new Warden client). Startup discovery uses that client (start the
   HTTP child first) or a short-lived client stopped before `warden.start`
   returns. Shutdown is bounded and fails in-flight requests conservatively.
3. **Requests:** a per-request `deadline.after(timeout_ms)`; the client
   ceiling equals `request_timeout_ms`; trust via `config.Anchors`.
4. **Adapter:** keep the application policy listed above and the failure
   mapping.
5. **Removal:** delete Warden's own resolution, TLS options, socket and
   head/body/chunk parsing and their OTP bindings, leaving one networking
   path; `transport.classify` delegates to `destination.classify`.
6. **Acceptance:** transport tests (as decided above), these probes as
   regression tests, all provider suites, browser journey and conformance,
   then update D11, `docs/SECURITY-REVIEW.md` and the oversight design.

## History

- **`b517725` (first run):** the stdlib bound blocked resolution (G1; tested
  with a widened bound in the copy); trust needed a temporary PEM file (G2);
  a request 100 ms after a peer close, and the second of two
  `connection: close` requests, were sent on the closing connection and
  failed `MayHaveBeenSent` (G3); `ManyHeaders` came back `ReceiveFailed`.
  Transport tests 17/19 with 6 differing rows; fast suite 123/126; security
  probes 8/9.
