# P1 — exact oidcc 3.9.0 calls, options, return shapes and error terms

> **Status (D13, 2026-10-01).** oidcc is no longer a Warden backend; these
> findings describe pinned oidcc 3.9.0, which remains a test-only oracle. The
> probe still runs in its provider suite.

Executable evidence: `test/integration/keycloak/keycloak_oidcc_probe_test.erl`
(`WARDEN_SUITE=keycloak gleam test`), against Keycloak 26.7.5 over verified
TLS through Warden's transport adapter. Source inspection is of oidcc tag
`v3.9.0` (commit `aa212d52d0140addf057c34917b734647401b34e`); the Hex tarball
`src/` and `include/` are byte-identical to that tag.

## Calls Warden uses

| Operation          | Call                                               | Required options                                                                                                                                                             |
| ------------------ | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Provider worker    | `oidcc_provider_configuration_worker:start_link/1` | `issuer`, `provider_configuration_opts.request_opts.http_adapter`, `backoff_type` (default `stop` terminates the worker on the first failed load)                            |
| Client context     | `oidcc_client_context:from_configuration_worker/4` | returns `{error, provider_not_ready}` until both metadata and JWKS are loaded                                                                                                |
| Authorization URL  | `oidcc_authorization:create_redirect_url/2`        | `redirect_uri`, `state`, `nonce`, `pkce_verifier`, `require_pkce`, `scopes`, `response_mode`, `preferred_auth_methods`, `request_opts`                                       |
| Code exchange      | `oidcc_token:retrieve/3`                           | `redirect_uri`, `nonce`, `pkce_verifier`, `require_pkce: true`, `trusted_audiences: []`, `validate_azp: client_id`, `preferred_auth_methods`, `refresh_jwks`, `request_opts` |
| Refresh            | `oidcc_token:refresh/3` (binary token)             | `expected_subject` (mandatory), `trusted_audiences`, `preferred_auth_methods`, `refresh_jwks`, `request_opts`                                                                |
| Userinfo           | `oidcc_userinfo:retrieve/3` (binary token)         | `expected_subject`, `request_opts`                                                                                                                                           |
| Introspection      | `oidcc_token_introspection:introspect/3`           | `client_self_only`, `preferred_auth_methods`, `request_opts`                                                                                                                 |
| Client credentials | `oidcc_token:client_credentials/2`                 | `scope`, `preferred_auth_methods`, `request_opts`                                                                                                                            |
| RP logout          | `oidcc_logout:initiate_url/3`                      | `post_logout_redirect_uri`, `state`                                                                                                                                          |

The `oidcc` facade module adds `refresh_jwks` (unknown-kid JWKS refresh via the
worker) and applies profiles; Warden calls the lower modules directly, so its
boundary must add `refresh_jwks` itself.

## Findings that change Warden's boundary

1. **Automatic PAR and request objects.** `create_redirect_url` pushes a PAR
   request (an HTTP call during URL creation) whenever metadata advertises
   `pushed_authorization_request_endpoint`, and signs a request object when
   `request_parameter_supported` is true. Keycloak advertises both; the raw URL
   contains `request_uri` and no `code_challenge`. PAR/JAR are later
   capability slices (design §4.8), so the boundary removes both fields from
   the client context before URL creation and rejects providers that require
   PAR (`require_pushed_authorization_requests`) or signed request objects.
2. **Plain PKCE fallback.** When metadata lacks `S256` but has `plain`,
   oidcc sends `code_challenge_method=plain`. Warden requires `S256` in
   metadata at startup and checks the produced URL carries the challenge it
   derived itself.
3. **Metadata-driven client authentication.** Without
   `preferred_auth_methods`, oidcc prefers `private_key_jwt`,
   `tls_client_auth`, `client_secret_jwt`, `client_secret_post`,
   `client_secret_basic`, `none` in that order and silently falls back to the
   next supported method when one is not possible. With a secret it picked
   `client_secret_jwt`, which Keycloak rejected (401). JWT assertions are
   signed with algorithms from provider metadata, which may include `none`.
   Warden passes exactly one configured method and filters signing
   algorithms against its own allowlist.
4. **ID-token signing algorithms come from provider metadata**
   (`id_token_signing_alg_values_supported`). Warden intersects them with its
   configured allowlist in the client context before validation.
5. **Error terms carry secrets.** `{missing_claim, Expected, Claims}` includes
   the full claim map; `{none_alg_used, TokenRecord}` includes every token;
   `{http_error, Status, Body}` includes the provider body. The boundary
   matches outer shapes only.
6. **Introspection conflates inactive with mismatch.** With the default
   `client_self_only: true`, an `{"active": false}` response (no `client_id`)
   returns `{error, client_id_mismatch}`. Warden passes
   `client_self_only: false` and classifies `active` itself.
7. **Transport errors pass through unchanged.** An adapter
   `{error, {warden_transport, Stage, Class}}` reaches the caller verbatim, so
   transmission evidence survives oidcc.

## Provider behaviour observed (Keycloak 26.7.5)

- Callback query carries `code`, `state` and RFC 9207 `iss`.
- Code replay returns `invalid_grant` **and revokes tokens already issued for
  that code**: the first exchange's refresh token then fails.
- Wrong verifier and wrong redirect URI return `invalid_grant` /
  `invalid_request` (400).
- Wrong nonce is detected by oidcc after the code was consumed at the provider.
- Refresh returns an ID token without `nonce`, with unchanged `auth_time`,
  and a rotated refresh token. Replaying the predecessor returns
  `invalid_grant` and revokes the session (subsequent userinfo: 401).
- Userinfo with a different expected subject: `{error, bad_subject}`.
- Introspection requires the introspecting client in the token audience
  (realm uses an audience mapper).
- Client credentials returns an access token and no ID token.
