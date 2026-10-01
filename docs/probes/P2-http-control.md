# P2 — HTTP control: TLS, destinations, redirects, deadlines, response size

> **Revised by D11 (2026-09-30).** The Erlang adapter `src/warden_http.erl`
> and its tests were replaced by the Gleam transport
> `src/warden/internal/transport.gleam` (with the oidcc adapter in
> `src/warden/internal/oidcc_transport.gleam`); the cases below are now in
> `test/warden/transport_test.gleam`. Policy and behaviour are unchanged.

Executable evidence: `test/warden_http_test.erl` (fast suite, real local TLS
servers from `test/warden_test_server.erl`, disposable PKI from
`test/warden_test_pki.erl`).

## Seam

oidcc 3.9.0 exposes `oidcc_http_adapter` (`request_opts.http_adapter`). The
adapter receives the complete request and returns an `httpc`-shaped response or
`{error, Reason}`; oidcc keeps decoding and error normalisation and passes
`Reason` through unchanged (`oidcc_discovery_uses_adapter_test`). The provider
worker uses `provider_configuration_opts.request_opts` for discovery and JWKS;
every other operation takes `request_opts` per call, so Warden's boundary sets
the adapter on every call.

## Decision: owned bounded adapter (`src/warden_http.erl`)

- The sibling `gleam-dream/http_gun` offers bounded collection, verified TLS,
  no redirects and `NotSubmitted`/`MayHaveBeenSent` evidence, but Gun/OTP own
  DNS resolution: it cannot resolve once, check every address and connect to
  the checked address. OIDC traffic is small request/response JSON over
  HTTP/1.1 and needs neither streaming nor HTTP/2.
- Warden therefore owns a minimal HTTP/1.1 client over OTP `ssl`. Revisit
  trigger: a need for HTTP/2 or streaming, or `http_gun` gaining a
  destination-policy hook; the adapter seam allows swapping without changing
  the oidcc boundary.

## Enforced and tested

| Property                                                                                          | Test                                                                                                                                              |
| ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| Peer verification with explicit trust anchors; system trust does not accept the test CA           | `untrusted_certificate_rejected_test`, `system_trust_does_not_accept_test_ca_test`                                                                |
| Hostname verification                                                                             | `wrong_host_certificate_rejected_test`                                                                                                            |
| Expired certificate                                                                               | `expired_certificate_rejected_test`                                                                                                               |
| HTTPS only; no userinfo                                                                           | `plain_http_rejected_test`, `userinfo_in_url_rejected_test`                                                                                       |
| Loopback/private/reserved destinations rejected before connecting (no request reaches the server) | `loopback_rejected_by_default_before_connect_test`, `private_resolution_rejected_test`, `mixed_resolution_rejected_test`, `classify_address_test` |
| Resolve once, connect to the checked address (DNS rebinding)                                      | `resolution_happens_once_test`                                                                                                                    |
| Optional host allowlist                                                                           | `allowed_hosts_enforced_test`                                                                                                                     |
| Redirects returned, never followed                                                                | `redirect_is_not_followed_test`                                                                                                                   |
| Declared oversize body rejected before reading                                                    | `declared_oversize_body_rejected_test`                                                                                                            |
| Endless chunked / close-delimited bodies bounded while reading                                    | `endless_chunked_body_rejected_test`, `close_delimited_oversize_rejected_test`                                                                    |
| Header count and line size bounded                                                                | `too_many_headers_rejected_test`, `oversized_header_line_rejected_test`                                                                           |
| Deadline covers the whole exchange                                                                | `slow_response_times_out_after_send_test`                                                                                                         |
| Compressed bodies rejected (none requested)                                                       | `compressed_body_rejected_test`                                                                                                                   |
| Header injection rejected before send                                                             | `header_injection_rejected_before_send_test`                                                                                                      |
| Transmission evidence: `not_sent` only before any byte is written                                 | `connection_refused_is_not_sent_test`, TLS cases                                                                                                  |

## Limits

- An over-long header line is buffered by OTP `ssl` up to `packet_size` plus
  one TLS record before it is rejected; body bounds apply to Warden's buffer,
  not to kernel or TLS buffers.
- Loopback is allowed only by explicit test configuration (local Keycloak and
  node-oidc-provider). Production configuration cannot allow it without an
  explicit policy value.
