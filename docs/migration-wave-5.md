# Wave 5 migration

Wave 5 follows relay's wave 5 verifier (relay 43baa65): a verifier receives
the request's correlation, and `VerificationError` has
`IssuedForAnotherResource`. One signature in warden breaks, and one function
is added.

## `warden/resource`

| Before                                                                    | After                                                                                   |
| ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `verifier(validator, token_value, accept, rejected: e, unavailable: e)`   | `verifier(validator, token_value, accept, on_error: fn(ErrorKind) -> e)`                |
| `ErrorKind`: `Rejected`, `Forbidden`, `Unavailable`                       | adds `WrongAudience`; `error_kind(AudienceMismatch)` is `WrongAudience`                 |
| `AudienceMismatch` could come from a token that also failed another check | `aud` is compared last: a mismatch means a token that is valid but for another resource |

```gleam
// Before: a wrong-audience token was a plain rejection.
resource.verifier(validator, authorization.token_value, attest,
  rejected: authorization.BearerRejected,
  unavailable: authorization.VerifierUnavailable)
|> authorization.verifier("warden-jwt", _)

// After: every kind is mapped, and Relay's own challenge is reachable.
let verify = resource.verifier(validator, authorization.token_value, attest,
  on_error: fn(kind) {
    case kind {
      resource.Rejected | resource.Forbidden -> authorization.BearerRejected
      resource.WrongAudience -> authorization.IssuedForAnotherResource
      resource.Unavailable -> authorization.VerifierUnavailable
    }
  })
use token, _correlation <- authorization.verifier("warden-jwt")
verify(token)
```

A token for another resource now gets 401 `invalid_token` with "issued for
another resource", with no policy to set. The introspection recipe applies
the request's correlation:

```gleam
// Before
use token <- authorization.verifier("warden-introspection")
case warden.introspect(client, authorization.token_value(token)) { .. }

// After: the provider call joins the MCP request in telemetry.
use token, correlation <- authorization.verifier("warden-introspection")
let client = warden.with_correlation(client, correlation)
case warden.introspect(client, authorization.token_value(token)) { .. }
```

(Relay's change, not Warden's: `authorization.verifier` takes
`fn(BearerToken, Correlation)` and `admit` takes the correlation.) The README
and the `resource` module doc carry the same recipe; `scripts/relay-recipe`
proves they are identical, compiles them against Relay, and runs six tests
through `admit` and `challenge`.

An earlier wave 5 draft added `AudiencePolicy.AudienceCheckedByCaller`. It
never shipped and is gone (D38).

## `warden/testing`

| Before                                                          | After                                                                                    |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `trust_anchor_pem(Provider) -> String` only; callers decoded it | adds `trust_anchor_der(Provider) -> BitArray`, the form HTTP Gun's `Anchors` takes (D39) |

```gleam
// Before: sso_portal decoded the PEM in its browser client (10 lines).
// After
http_gun_config.Anchors([testing.trust_anchor_der(provider)])
```

## Round 8: scopes per login in `warden/testing` (additive)

Verified approvers (fabric) need an authenticated user who lacks a scope.
The provider granted the scopes the client requested, so a test could not
sign in mallory without `approve:refund`.

| Before                                              | After                                                                           |
| --------------------------------------------------- | ------------------------------------------------------------------------------- |
| `/authorize` grants the scopes the client requested | adds `with_granted_scopes(ProviderOptions, subject, scopes) -> ProviderOptions` |
| the grant could not change after start              | adds `set_granted_scopes(Provider, subject, scopes) -> Nil`                     |

```gleam
// After: ada may approve refunds, mallory signs in but may not.
let assert Ok(provider) =
  testing.start_provider(
    testing.provider_options()
    |> testing.with_granted_scopes("ada", ["openid", "approve:refund"])
    |> testing.with_granted_scopes("mallory", ["openid"]),
  )
// ... a login with login_hint "mallory" ...
let assert Ok(claims) = resource.verify(validator, token)
resource.scopes(claims)  // ["openid"]
```

The granted list replaces the requested scopes exactly (it is granted even
if unrequested; `openid` is not added), and a subject with no entry gets
the requested ones. The list is in the access token's `scope` claim, the
token response and introspection. `LoginDecision`, `SignIn` and `with_login`
are unchanged, so no dependent breaks (D40). `resource.scopes`, `subject`
and `issuer` already exist and need no change. Dependent: fabric's
`approvers_warden` consumer (round 8) uses it.

## Decided, not changed

- No JWK or JWKS trust anchor ([D39](decisions.md)); `config.Trust` stays
  `SystemTrust | TrustAnchorsPem(String)`.

## Dependents

Found with `grep` over `/code/gleam-dream/*/src`, `*/test`, `*/integrations`,
`*/consumers`, `*/examples` and `oversight/apps`.

| Dependent                                                  | Uses                                                                                                             | What changes                                                                                                                                                                                                                                                                                                                              |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `oversight/apps/secure_mcp` `auth.gleam:19-30` (and `:44`) | `resource.verifier(.., rejected:, unavailable:)`; `authorization.verifier(name, fn(token) ..)` for introspection | Breaks on the relay and warden signatures. Replace the two labelled arguments with `on_error: refuse` (above), take `use token, _correlation <-` in the JWT verifier, and `use token, correlation <-` plus `warden.with_correlation` in the introspection one. `token_for_another_audience_test` then expects `IssuedForAnotherResource`. |
| `oversight/apps/sso_portal` browser client                 | decodes `testing.trust_anchor_pem` itself                                                                        | May use `testing.trust_anchor_der` and delete the decoding.                                                                                                                                                                                                                                                                               |
| `warden/consumer` (`warden_reference_test.gleam`)          | `resource.verifier` with its own refusal type                                                                    | Migrated here: `refuse` maps to `WrongResource`.                                                                                                                                                                                                                                                                                          |

## Round 9: validation maintenance

The in-memory store now checks capacity before inspecting its FIFO, avoiding unnecessary queue work while there is room. Eviction and expiry semantics stay unchanged. The Relay recipe gate creates its generated source directory on a clean checkout. No public signatures or dependent application code change; the existing compiled verifier recipe remains the composition boundary.


The review validation pass also fixes the introspection-expiry fixture. Before,
it froze the client clock before startup but calculated the provider's expiry
when the request arrived, so a wall-clock second boundary changed the expected
result. The fixture now supplies one fixed expiry and tests the client exactly
at that expiry and one second before it. No production behavior, public API or
dependent application changes.
