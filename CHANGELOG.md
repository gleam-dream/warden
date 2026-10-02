# Changelog

All notable changes to `warden` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the package
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The design
decisions behind these entries are in [docs/decisions.md](docs/decisions.md),
and the evidence for each wave in [docs/PROGRESS.md](docs/PROGRESS.md).

## Unreleased

### Added

- An OpenID Connect relying party (`warden`, `warden/config`): discovery,
  key caching, the authorization code flow with PKCE S256, nonce and state,
  query and form-post callbacks bound to the browser, and ID-token
  validation on gose and kryptos. One backend, written in Gleam; oidcc
  3.9.0 is a test-only differential oracle.
- Atomic login transactions (replay, concurrent callbacks, expiry) and a
  custody owner for sessions with absolute and idle lifetimes, refresh with
  at most one outstanding request per generation, and recovery values for
  uncertain custody installation or refresh publication.
- Userinfo, client credentials, token introspection and RP-initiated
  logout.
- Client authentication by `client_secret_basic`, `client_secret_post`,
  `client_secret_jwt` and `private_key_jwt`, never falling back to another
  method. Client secrets, signing keys, access tokens, browser bindings,
  session references and raw claims are held in closures, so
  `string.inspect` and crash reports do not print them.
- HTTPS through a supervised HTTP Gun client per Warden client, under a
  destination policy, verified TLS and bounded responses.
- An explicit opt-in, `AssumeS256WhenUnadvertised`, for providers that do
  not advertise PKCE methods; the default still requires advertised S256.
- Typed Sinal observations of provider requests (`warden/observation`).
- Tests that `string.inspect` of settings and validated configurations
  (with every client authentication method), `Secret`, `SigningKey`,
  `AccessToken`, session access-token results, refresh results, client
  credentials tokens, introspection results and their errors prints no
  client secret, private key or token.

### Fixed

- `docs/PROGRESS.md` no longer lists D7 as an open decision; the decision
  register records it as resolved.
