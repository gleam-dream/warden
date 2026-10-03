# Wave 5 migration

Wave 5 adds one policy variant and changes no signature. An existing build
keeps compiling and behaving as before: the new variant is opt-in.

## `warden/resource`: a wrong-audience token reaches Relay

| Before                                                                                                            | After                                                                                                                           |
| ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `AudiencePolicy`: `ExactAudience`, `AudienceIncluded`                                                             | adds `AudienceCheckedByCaller`: Warden skips only the `aud` comparison, and `audiences(claims)` returns what the token names    |
| a token for another resource: `verify` gives `AudienceMismatch`; `verifier` gives `rejected` (Relay: generic 401) | unchanged by default; with `AudienceCheckedByCaller`, `verifier` calls `accept`, and Relay's `admit` gives `ResourceNotGranted` |
| `resource.verifier(validator, token_value, accept, rejected:, unavailable:)`                                      | unchanged                                                                                                                       |

```gleam
// Before: Relay saw BearerRejected, so the challenge said "invalid or expired".
let validator = resource.new(client, audience: mcp_url)
authorization.verifier("warden-jwt", resource.verifier(validator, authorization.token_value, attest,
  rejected: authorization.BearerRejected, unavailable: authorization.VerifierUnavailable))

// After: Relay compares the audiences, so Warden leaves that check to it.
let validator =
  resource.new(client, audience: mcp_url)
  |> resource.with_audience_policy(resource.AudienceCheckedByCaller)
// the rest is unchanged; `attest` must pass `resource.audiences(claims)` on.
```

A token for another resource now gets 401 `invalid_token` with "issued for
another resource" and Relay's `ResourceNotGranted` telemetry decision. A
token with several audiences is refused the same way. Expired,
forged, unsigned, wrong-issuer, wrong-`typ` and unknown-key tokens are still
`BearerRejected`, and a missing scope is still Relay's 403.

Use the policy only when something compares `audiences(claims)`. Without
that, any validly signed token from the issuer passes. Direct `verify` users
keep the default.

The Relay verifier recipe in the README and in the `resource` module doc
changed from `jwt_verifier(validator)` to `jwt_verifier(client, resource_url)`
so the policy is in sight. `scripts/relay-recipe` compiles it and runs five
tests through Relay (`relay_consumer/test`).

## Decided, not changed

- No JWK or JWKS trust anchor ([D39](decisions.md)). `config.Trust` stays
  `SystemTrust | TrustAnchorsPem(String)`.
- Relay could add a wrong-audience `VerificationError` variant (additive);
  nothing here needs it.

## Dependents

Found with `grep` over `/code/gleam-dream/*/src`, `*/test`, `*/integrations`,
`*/consumers`, `*/examples` and `oversight/apps`.

| Dependent                                               | Uses                                                                        | Effect                                                                                                                                                                                                                                                                      |
| ------------------------------------------------------- | --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `oversight/apps/secure_mcp` (`auth.gleam`, `app.gleam`) | `resource.verifier` with `resource.new(resource_server, audience: mcp_url)` | Builds unchanged, behaves unchanged. To get Relay's precise challenge, add `\|> resource.with_audience_policy(resource.AudienceCheckedByCaller)` at `app.gleam:100`; `token_for_another_audience_test` then expects `ResourceNotGranted` and "issued for another resource". |
| `warden/consumer` (`warden_reference_test.gleam`)       | `resource.verifier` with its own attestation type                           | Unchanged.                                                                                                                                                                                                                                                                  |
