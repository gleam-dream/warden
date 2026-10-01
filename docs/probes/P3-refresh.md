# P3 — actual refresh responses through pinned oidcc

> **Status (D13, 2026-10-01).** oidcc is no longer a Warden backend; these
> findings describe pinned oidcc 3.9.0, which remains a test-only oracle. The
> probe still runs in its provider suite.

Executable evidence: `test/integration/node/node_refresh_probe_test.erl`
(node-oidc-provider 9.12.2) and the refresh section of
`test/integration/keycloak/keycloak_oidcc_probe_test.erl` (Keycloak 26.7.5).

| Case                                    | Provider                       | Raw oidcc 3.9.0 result                             | Consequence for Warden                                                                                                                                           |
| --------------------------------------- | ------------------------------ | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID token present, refresh token rotated | both                           | `{ok, #oidcc_token{}}`                             | Publish replacement after continuity checks                                                                                                                      |
| ID token absent                         | node (post-processed response) | `{error, sub_invalid}` — the response is discarded | Provider already rotated: the predecessor then returns `invalid_grant`. Warden classifies this as a quarantined response, never as success or definite rejection |
| Refresh token omitted                   | node                           | `{ok, #oidcc_token{refresh = none}}`               | Retain the current refresh token explicitly                                                                                                                      |
| Subject changed                         | node                           | `{error, sub_invalid}`                             | Quarantined response (provider may have rotated)                                                                                                                 |
| Nonce changed                           | node                           | accepted (refresh forces `nonce: any`)             | Warden checks nonce continuity itself                                                                                                                            |
| `auth_time` changed                     | node                           | accepted                                           | Warden checks `auth_time` continuity itself                                                                                                                      |
| Response lost after rotation            | node (`delayMs`)               | `{error, {warden_transport, sent, timeout}}`       | Quarantine; the predecessor is already invalid                                                                                                                   |
| Provider 503 after processing           | node                           | `{error, {http_error, 503, _}}`                    | Uncertain: quarantine                                                                                                                                            |
| Narrowed scope without `openid`         | Keycloak                       | ID token still returned                            | Keycloak cannot produce the absent case                                                                                                                          |
| Refresh-token reuse                     | Keycloak                       | `invalid_grant`, session revoked                   | Never retry a possibly transmitted refresh token                                                                                                                 |

## Absent-ID-token limitation (reproduced)

The pinned refresh overload requires `expected_subject` and rejects a response
without an ID token as `sub_invalid`, after the provider has accepted the
request. The default Warden adapter therefore **does not support** refresh
responses that omit the ID token: it reports `RefreshResponseQuarantined`
with `IdTokenAbsentUnsupported`, retains the quarantine, and never fabricates
authentication evidence. OIDC Core §12.2 permits the omission, so this is a
declared adapter limitation, not a Warden policy. Supporting it requires a
refresh adapter that does not route through `oidcc_token:refresh/3`; that
choice is recorded as an open decision.
