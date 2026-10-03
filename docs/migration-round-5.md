# Round 5 migration

Round 5 adds two things and breaks no dependent's build:

- `warden/testing` serves a scripted login page at `/authorize`, so tests
  follow the application's own login redirect over HTTPS. It can also
  revoke one access token and set the access-token audience after start
  ([D35](decisions.md)).
- A login may choose its redirect URI from an exact allowlist configured on
  the client ([D36](decisions.md)). The redirect URI is still fixed when
  `warden.new` runs ([D37](decisions.md)).

Every change adds a function, a variant or a record field. The new
`LoginOptions` field breaks only a full `LoginOptions(...)` construction
without `..default_login()`, and the new variants break only an exhaustive
`case` on `ConfigError` or `LoginOptionProblem`. Neither occurs in the
dependents.

## `warden/config`

| Before                                                           | After                                                                                                                                         |
| ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| one redirect URI per client: `config.new(.., redirect_uri:, ..)` | unchanged, and still the ordinary path                                                                                                        |
| —                                                                | `config.with_allowed_redirect_uris(config, List(String)) -> Config`: further registered callback addresses a login may choose                 |
| —                                                                | `ConfigError.InvalidAllowedRedirectUri(String)`: an allowed URI breaks the redirect URI rule (absolute, no fragment, `https` unless loopback) |
| —                                                                | `ConfigError.AllowedRedirectUrisNeedLogin`: set on `service_client` or `resource_server`                                                      |

```gleam
// Before: a second callback address needed a second client.
let admin = config.new(issuer:, client_id:, redirect_uri: admin_callback, authentication:)

// After: one client, the default plus an allowlist.
config.new(issuer:, client_id:, redirect_uri: app_callback, authentication:)
|> config.with_allowed_redirect_uris([admin_callback])
```

## `warden`: login

| Before                                                                                               | After                                                                                                                                                                      |
| ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `LoginOptions(scopes:, prompt:, max_age:, login_hint:, acr_values:, ui_locales:, extra_parameters:)` | adds `redirect_uri: Option(String)`; `default_login()` sets `None` (the configured URI)                                                                                    |
| —                                                                                                    | `LoginOptionProblem.RedirectUriNotAllowed`, returned as `Error(InvalidLoginOption(RedirectUriNotAllowed))` by `begin_login`; `login_error_action` gives `FixConfiguration` |

```gleam
// Before
warden.begin_login(client, request, warden.default_login())

// After, unchanged for the configured URI; a login that picks another:
warden.begin_login(
  client,
  request,
  warden.LoginOptions(..warden.default_login(), redirect_uri: Some(admin_callback)),
)
```

The match is exact. `admin_callback <> "/"`, another case, an explicit
`:443` or a percent-encoded path is refused.

## `warden/testing`

| Before                                                                             | After                                                                                                                                             |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| no `/authorize`; only `testing.authorize(provider, redirect, subject:)` in process | `GET` and `POST /authorize` on the provider; `testing.authorize` unchanged (it also requires `response_type=code` now, which Warden always sends) |
| —                                                                                  | `pub type LoginDecision { SignIn(subject: String) Refuse(error: String) }`; `SignIn` uses the request's `login_hint` when present                 |
| —                                                                                  | `with_login(ProviderOptions, LoginDecision) -> ProviderOptions` (default `SignIn("test-user")`), `set_login(Provider, LoginDecision) -> Nil`      |
| revoking one access token: post to `/revoke` by hand                               | `revoke_access_token(Provider, String) -> Nil`                                                                                                    |
| `with_access_token_audiences` before start only                                    | `set_access_token_audiences(Provider, List(String)) -> Nil` after start                                                                           |
| `RequestCounts(discovery:, keys:, ..)`                                             | adds `authorizations: Int`                                                                                                                        |

A login hook in production code becomes an ordinary redirect:

```gleam
// Before: the app answered for the provider.
case testing.authorize(provider, redirect, subject: user) {
  Ok(callback) ->
    warden.login_response(wisp.response(303), redirect)
    |> wisp.set_header("location", uri.to_string(request.to_uri(callback)))
  Error(_) -> wisp.response(502)
}

// After: production code only; the test browser follows Location to the
// provider (trusting testing.trust_anchor_pem) and back to /callback.
warden.login_response(wisp.response(303), redirect)
```

Choosing the user:

```gleam
// At start, or between logins:
testing.provider_options() |> testing.with_login(testing.SignIn("ada"))
testing.set_login(provider, testing.SignIn("bob"))
testing.set_login(provider, testing.Refuse("access_denied"))
// Per login, from the app: LoginOptions(..default_login(), login_hint: Some(user))
```

Revocation and audience:

```gleam
// Before: a hand-built RFC 7009 request with the client's credentials.
client.revoke_access_token(issuer, client_id, client_secret, token)
// After
testing.revoke_access_token(provider, token)

// Before: the port reserved first so the audience could name it.
testing.provider_options() |> testing.with_access_token_audiences([mcp_url])
// After: also possible once the app listens.
testing.set_access_token_audiences(provider, [mcp_url])
```

A revoked access token is inactive at introspection and userinfo at once.
`warden/resource` keeps accepting it until `exp`, because a JWT access token
carries no revocation channel. A test of revocation uses introspection, or
short lifetimes with local validation.

## Dependents

Found with `grep` over `/code/gleam-dream/*/src`, `*/test`,
`*/integrations`, `*/consumers` and `oversight/apps`. Only two apps import
Warden. Both build unchanged; the changes let them delete glue.

| Dependent                   | Uses                                                                                                                                                                                      | What it can remove                                                                                                                                                                                                                                                                                   |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `oversight/apps/sso_portal` | `testing.authorize` and `warden.login_response` in `app.gleam` `provider_login_page`; the `Context.login_response` hook in `web.gleam`; `with_access_token_audiences`; `server.free_port` | `Context.login_response` and `provider_login_page`: the scripted browser follows `/login` to the provider. The billing API's deny list can become introspection, or stay as the honest local-validation model. `free_port` stays: the portal's redirect URI must be known before `warden.new` (D37). |
| `oversight/apps/secure_mcp` | `testing.authorize` in `web.gleam` `/login?as=<user>`; `client.revoke_access_token` posting to `/revoke`; `free_port` with `with_access_token_audiences([mcp_url])` in `app.gleam`        | the `/login` answer for the provider (pass `login_hint: Some(user)` and redirect); `client.revoke_access_token` (use `testing.revoke_access_token`). The port reservation stays while Warden's redirect URI and the MCP URL name the port; the audience alone no longer requires it.                 |
