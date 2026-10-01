# Prompt: destination policy and DNS pinning for http_gun

Paste the section below into a session working in `/code/gleam-dream/http_gun`.

---

Add an explicit **destination policy** to `http_gun` so a client can refuse
network destinations before any connection is opened, and so the address it
checked is the address it connects to. The consumer is Warden
(`/code/gleam-dream/warden`), an OpenID Connect relying party that must stop
server-side request forgery through provider metadata (discovery, JWKS,
token, userinfo, introspection endpoints). Warden currently owns a minimal
HTTP/1.1 client only because http_gun cannot do this; with the feature it
will adopt http_gun for all provider traffic.

## Required behaviour

1. **Resolve once, then decide.** For a hostname origin, resolve A and AAAA
   records once, within the request deadline. Every resolved address must
   pass the policy; if any address fails, refuse the origin (a mixed answer
   is a rebinding signal). An IP-literal origin is checked directly.
2. **Connect to what was checked.** Open Gun to an address from that same
   answer (Gun accepts an IP tuple as host) and keep TLS verification bound
   to the original name: `server_name_indication` = original host and
   hostname checking against it (`customize_hostname_check` with
   `public_key:pkix_verify_hostname_match_fun(https)`). For IP-literal
   origins, verify against the IP. No second resolution may happen between
   the check and the connect.
3. **Classification.** Classify each address as public, loopback, private
   (RFC 1918, RFC 6598 shared, IPv6 unique-local) or reserved (unspecified,
   link-local incl. 169.254.0.0/16 and fe80::/10, multicast, broadcast,
   documentation ranges, benchmarking 198.18.0.0/15, 192.0.0.0/24,
   192.88.99.0/24, 6to4 2002::/16, 100::/64, 240.0.0.0/4). IPv4-mapped
   (`::ffff:a.b.c.d`) and NAT64 (`64:ff9b::/96`) addresses are classified by
   their embedded IPv4 address. Reserved is never allowed.
4. **Policy shape** (pure, validated with `config.validate`): allow public
   (default true), allow loopback (default false), allow private (default
   false), optional host allowlist (exact, case-insensitive), and an
   injectable resolver for tests (default `inet:getaddrs/3` for `inet` and
   `inet6`). The default config must reject loopback, private and reserved.
5. **Evidence and errors.** Every refusal, resolution failure or empty answer
   happens before submission: report it as a typed failure with
   `NotSubmitted` evidence and no free-form content (e.g. a new
   `DestinationRejected` / `ResolutionFailed` reason). Never fall back to
   Gun's own resolution.
6. **Pools.** Connection reuse must not bypass the policy: a pooled
   connection was opened to a checked address; key or invalidate pooled
   connections so that a policy change or a new resolution never reuses a
   connection to an address the current policy would refuse. State the rule
   in BOUNDS.md.
7. **Plain HTTP** remains possible for clients that allow it; Warden will
   only use HTTPS with redirects off (http_gun already never follows
   redirects).

## Acceptance tests (loopback servers, no network)

Mirror the cases in Warden's `test/warden_http_test.erl`:

- loopback refused by default, and the server observes no connection;
- loopback allowed only with the explicit setting;
- a resolver returning `10.0.0.7` → refused, `NotSubmitted`;
- a mixed answer (public + `169.254.169.254`) → refused;
- rebinding: a resolver that returns `127.0.0.1` on its first call and
  `10.0.0.1` afterwards is called exactly once and the request reaches the
  first answer (allow loopback for this test);
- host allowlist refuses other hosts;
- classification table including the IPv4-mapped and NAT64 cases above;
- TLS still verifies the original hostname when connecting by IP (a
  wrong-host certificate is refused);
- resolution failure → typed `NotSubmitted` failure.

Keep the existing gates green (`./dev/env sh dev/gate fast` and `full`).
Document the feature in README.md and BOUNDS.md, including that DNS answers
are trusted for the duration of one connection only.
