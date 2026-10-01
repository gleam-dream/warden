# Prompt: destination policy and DNS pinning for http_gun

Paste the section below into a session working in `/code/gleam-dream/http_gun`.
Revised 2026-10-01 with the lessons of Warden's internal security review
(`docs/SECURITY-REVIEW.md`, findings T1–T8).

---

Add an explicit **destination policy** to `http_gun` so a client can refuse
network destinations before any connection is opened, and so the address it
checked is the address it connects to. The consumer is Warden
(`/code/gleam-dream/warden`), an OpenID Connect relying party that must stop
server-side request forgery through provider metadata (discovery, JWKS,
token, userinfo, introspection endpoints). Warden currently owns a minimal
HTTP/1.1 client in Gleam (`src/warden/internal/transport.gleam`) only
because http_gun cannot do this; with the feature it will adopt http_gun for
all provider traffic. Read Warden's transport and its tests
(`test/warden/transport_test.gleam`) first: they are the reference
behaviour, including the defects listed under "Known traps".

## Required behaviour

1. **Resolve once, then decide.** For a hostname origin, resolve A and AAAA
   records once, within the request deadline. Every resolved address must
   pass the policy; if any address fails, refuse the origin (a mixed answer
   is a rebinding signal). An IP-literal origin is checked directly.
2. **Connect to what was checked.** Open Gun to an address from that same
   answer (Gun accepts an IP tuple as host) and keep TLS verification bound
   to the original name: `server_name_indication` = original host and
   hostname checking against it (`customize_hostname_check` with
   `public_key:pkix_verify_hostname_match_fun(https)`). No second resolution
   may happen between the check and the connect.
3. **IP-literal origins.** Pass **no** `server_name_indication` option at
   all, so OTP checks the certificate's `iPAddress` SAN against the
   connected address. Never set it to `disable`: in OTP `ssl` that also
   switches the certificate name check off, accepting any certificate that
   chains to the trust anchors (Warden finding T1).
4. **Classification.** Classify each address as public, loopback, private
   or reserved:
   - private: RFC 1918, RFC 6598 shared (100.64.0.0/10), IPv6 unique-local
     (fc00::/7);
   - reserved: unspecified, link-local (169.254.0.0/16, fe80::/10),
     multicast, broadcast, 240.0.0.0/4, documentation (192.0.2.0/24,
     198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32, 3fff::/20),
     benchmarking (198.18.0.0/15, 2001:2::/48), 192.0.0.0/24,
     192.88.99.0/24, 6to4 2002::/16, 100::/64, Teredo 2001::/32, ORCHID
     2001:10::/28 and 2001:20::/28;
   - cloud metadata services are reserved even inside ranges that
     `allow_private` admits: 100.100.100.200 (Alibaba) and fd00:ec2::254
     (AWS IPv6), in addition to 169.254.169.254;
   - IPv4-mapped (`::ffff:a.b.c.d`) and NAT64 (`64:ff9b::/96`) addresses are
     classified by their embedded IPv4 address. Reserved is never allowed.
5. **Policy shape** (pure, validated with `config.validate`): allow public
   (default true), allow loopback (default false), allow private (default
   false), optional host allowlist (exact, case-insensitive), and an
   injectable resolver for tests (default `inet:getaddrs/3` for `inet` and
   `inet6`). The default config must reject loopback, private and reserved.
   Document that the allowlist restricts host names, not ports.
6. **Evidence and errors.** Every refusal, resolution failure or empty answer
   happens before submission: report it as a typed failure with
   `NotSubmitted` evidence and no free-form content (e.g. a new
   `DestinationRejected` / `ResolutionFailed` reason). Never fall back to
   Gun's own resolution. Never report `NotSubmitted` once a request byte
   may have been written.
7. **Deadline covers the send.** One deadline covers resolution, connect,
   handshake, send and every receive. TLS sends do not time out by default:
   bound them (`send_timeout` with `send_timeout_close`, or an equivalent)
   and/or cap request bodies, so a peer that stops reading cannot stall a
   request past its deadline (finding T3).
8. **No late messages.** After a timeout or cancellation, no Gun message
   (response parts, `gun_down`, monitor `DOWN`) may remain in the caller's
   mailbox: callers are long-lived processes that log unexpected messages,
   and response data can hold tokens (Warden finding F4).
9. **Pools.** Connection reuse must not bypass the policy: a pooled
   connection was opened to a checked address; key or invalidate pooled
   connections so that a policy change or a new resolution never reuses a
   connection to an address the current policy would refuse. State the rule
   in BOUNDS.md.
10. **Plain HTTP** remains possible for clients that allow it; Warden will
    only use HTTPS with redirects off (http_gun already never follows
    redirects).

## Known traps (from Warden's review; check them, add a test for each)

- Header limits must cover the whole head, including the read that
  completes it, not only the bytes before the last read (T4).
- Response framing must be strict if http_gun parses anything itself:
  CRLF only, no control characters (HTAB aside) in the status line or
  header values, digits only in `content-length`, hex digits only in chunk
  sizes (T7). If Gun/cowlib does the parsing, add tests proving it rejects
  these.
- An IPv6 literal is bracketed in the `Host` header on every port,
  including 443 (T6).
- A close-delimited body cannot be distinguished from a truncated one when
  the peer closes without `close_notify` (T5); document it.

## Acceptance tests (loopback servers, no network)

Mirror the cases in Warden's `test/warden/transport_test.gleam`:

- loopback refused by default, and the server observes no connection;
- loopback allowed only with the explicit setting;
- a resolver returning `10.0.0.7` → refused, `NotSubmitted`;
- a mixed answer (public + `169.254.169.254`) → refused;
- rebinding: a resolver that returns `127.0.0.1` on its first call and
  `10.0.0.1` afterwards is called exactly once and the request reaches the
  first answer (allow loopback for this test);
- host allowlist refuses other hosts;
- classification table including the IPv4-mapped, NAT64, metadata, Teredo,
  ORCHID and 3fff::/20 cases above;
- TLS verifies the original hostname when connecting by IP (a wrong-host
  certificate is refused);
- an IP-literal URL (`https://127.0.0.1:PORT/`) is accepted with a
  certificate whose SAN is `IP:127.0.0.1` and refused with a wrong-host
  certificate;
- a request to a server that never reads its input ends at the deadline;
- after a timed-out request, the caller's mailbox gained no message;
- resolution failure → typed `NotSubmitted` failure.

Keep the existing gates green (`./dev/env sh dev/gate fast` and `full`).
Document the feature in README.md and BOUNDS.md, including that DNS answers
are trusted for the duration of one connection only.

Warden switches to http_gun only when a release contains this feature and
Warden's own transport tests pass unchanged through it.
