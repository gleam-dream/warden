# P4 — driving the OpenID RP conformance suite through a Warden reference RP

Status: feasible; images pulled; execution scheduled for W6.

- Suite: `gitlab.com/openid/conformance-suite` `release-v5.3.1` (commit
  `440eec8bac7b12b7389d7ca9cbc459b53507a443`, MIT). Prebuilt multi-arch images
  `registry.gitlab.com/openid/conformance-suite:release-v5.3.1` and
  `…/nginx:release-v5.3.1`, plus `mongo:6.0.13`
  (`test/conformance/docker-compose-prebuilt.upstream.yml`, fetched unchanged
  from that tag).
- Dev profile (`SPRING_PROFILES_ACTIVE=dev`) disables API authentication.
  Base URL `https://localhost.emobix.co.uk:8443` (public DNS → 127.0.0.1).
  Its nginx certificate is self-signed without SAN; Warden will not disable
  verification, so the harness mounts a certificate from the disposable test
  PKI for `localhost.emobix.co.uk` and trusts that CA explicitly.
- API: `POST /api/plan?planName&variant`, `POST /api/runner?test&plan`,
  `GET /api/runner/{id}` (exposes the redirect the suite built),
  `GET /api/info/{id}`, `GET /api/log/{id}`, `GET /api/plan/exporthtml/{id}`.
- Upstream practice: `erlef/oidcc_conformance` (`b632d974…`, Apache-2.0) used
  the hosted suite with a manually driven browser; `panva/openid-client`
  (`v6.8.8`, MIT) drives a local suite headlessly in CI (Basic plan only).
- Retained plans: Basic, Config, Form Post, third-party initiated login,
  RP-initiated logout, refresh (non-certification). Known upstream friction:
  key-rotation modules are skipped in the suite's own CI (issue #837);
  logout needs a back-channel or front-channel URI; 3rd-party login needs
  browser-queue polling.
- Local passes are regression evidence only. Certification requires a
  hosted submission for an exact Warden release.
