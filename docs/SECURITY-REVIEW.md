# Internal security review (2026-10-01)

An internal adversarial review of Warden-owned code, done before the
independent external review the design requires (design §6, release gates).
It does not replace that review and certifies nothing.

## Method

Four reviewers worked in parallel, each read-only on one trust boundary:

| Area                               | Scope                                                                                             |
| ---------------------------------- | ------------------------------------------------------------------------------------------------- |
| Transport (T)                      | `internal/transport.gleam`: SSRF, TLS, URL and response parsing, bounds, deadlines, send evidence |
| Token verification (J)             | `internal/native/{jose,provider,client}.gleam`, identity acceptance in `warden.gleam`             |
| Login and custody (F)              | `warden.gleam` flows, `internal/{callback,transaction_store,custody_store,call}.gleam`            |
| Config, secrets, reference app (C) | `config.gleam`, `secure.gleam`, `observation.gleam`, secret handling, `consumer/`                 |

Reviewers confirmed findings by running code (minted tokens, local TLS
servers, store probes) where they could. Each finding was then reproduced
here with a failing test before it was fixed (test-driven), except where
noted. Severity is the reviewers', adjusted after verification.

## Findings

No finding allowed a third party to forge an identity against a correctly
configured deployment. The two high findings were a TLS name-check bypass
for IP-literal hosts (T1) and client credentials visible in inspected values
(C1).

| ID       | Severity   | Finding                                                                                                           | Status                                                                 | Test                                                                                                                  |
| -------- | ---------- | ----------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| T1       | high       | IP-literal hosts disabled the certificate name check (`server_name_indication: disable`)                          | fixed `b7a88ca`                                                        | `ip_literal_hosts_are_verified_against_the_certificate_test`                                                          |
| C1       | high       | Client secret / private JWK printed by `string.inspect` of a `Client`                                             | fixed `56ea68a`                                                        | `warden_inspect_test`                                                                                                 |
| F1 / C3  | high       | Unauthenticated `begin_login` traffic could fill the pending-login store (tombstones counted, O(n) sweep per put) | fixed `2c1da28`; volume limits remain an application duty              | `transaction_store_test`                                                                                              |
| F3 / C2  | medium     | Binding, session reference, raw claims and token-bearing recovery values printed by `string.inspect`              | fixed `56ea68a`                                                        | `warden_inspect_test`                                                                                                 |
| F4       | medium     | Late store replies (login material, tokens) left in the caller's mailbox                                          | fixed `e043508`                                                        | `late_replies_do_not_reach_the_caller_test`                                                                           |
| J1 / C9  | medium     | RSA keys below 2048 bits accepted for verification and for `private_key_jwt`; non-signing keys accepted at import | fixed `922f18b`                                                        | `key_strength_test`                                                                                                   |
| J2       | medium     | Provider cache did network I/O inside its actor; slow provider blocked every login                                | fixed `c2429be`                                                        | `provider_cache_test`                                                                                                 |
| C5 / C6  | medium     | Reference app: binding cookie `Secure` followed the request scheme; no `__Host-` prefix                           | fixed `dd10381`                                                        | `consumer/test/protect_test.gleam`                                                                                    |
| C4       | medium     | Reference app: session lifetime enforced only by the browser                                                      | fixed `dd10381` (reference app)                                        | `protect_test`                                                                                                        |
| F2       | medium     | Custody entries never expire and have no capacity bound                                                           | **owner decision** (below)                                             | —                                                                                                                     |
| F5       | medium/low | Installation recovery could resurrect a logged-out session or install a second session after receipt eviction     | fixed `7686e4f`                                                        | `custody_store_test`, `lost_custody_acknowledgement_recovers_without_exchange_test`                                   |
| F6       | low        | Refresh rejected with an unrecognised OAuth error released the generation                                         | fixed `2a917d5`                                                        | `uncertain_and_invalid_refresh_outcomes_quarantine_test`                                                              |
| F7       | low        | A refresh whose dispatcher died stayed "in progress" forever                                                      | fixed `061595d`                                                        | `a_dispatcher_that_dies_quarantines_the_generation_test`, `an_orphaned_reservation_accepts_only_its_publication_test` |
| F8       | low        | Callback query kept `+` literally, accepted stray `%`, allowed space in `error`                                   | fixed `7378631`                                                        | `callback_parsing_table_test`                                                                                         |
| F9       | low        | Pending-login expiry uses the wall clock (NTP steps shift lifetimes)                                              | deferred                                                               | —                                                                                                                     |
| J3       | low        | Zero clock skew also applies to `iat`/`nbf`; a provider clock ahead by under a second fails a fraction of logins  | **owner decision** (below)                                             | —                                                                                                                     |
| J4       | low        | Non-string `azp` / `at_hash` treated as absent                                                                    | fixed `ee413bc`                                                        | `mistyped_azp_and_at_hash_are_rejected_test`                                                                          |
| J5       | low        | Signed userinfo without `exp` rejected                                                                            | fixed `ee413bc`                                                        | `signed_userinfo_without_exp_verifies_test`                                                                           |
| J6       | low        | Authorization endpoint with its own query failed every login                                                      | fixed `69a4291`                                                        | `authorization_endpoint_query_is_preserved_test`                                                                      |
| J7 / C12 | low        | Empty secrets and short `client_secret_jwt` secrets passed validation                                             | fixed `3ac90f5`                                                        | `client_secrets_must_be_usable_test`, `jwt_secret_length_limits_the_hmac_algorithms_test`                             |
| J8       | low        | Ed448 keys verified EdDSA tokens (at_hash computed for Ed25519 only)                                              | fixed `ee413bc`                                                        | `ed448_keys_are_not_used_test`                                                                                        |
| J9       | low        | Future `auth_time` satisfied any `max_age`                                                                        | fixed `2a917d5`                                                        | `future_authentication_time_fails_max_age_test`                                                                       |
| J10      | low        | Kid-less fallback key mismatch yields `bad_signature` without a key refresh                                       | deferred (availability only)                                           | —                                                                                                                     |
| J11      | low        | Insecure end-session endpoint received the ID-token hint                                                          | fixed `69a4291`                                                        | `insecure_end_session_endpoint_is_refused_test`                                                                       |
| J12      | low        | Non-Bearer `token_type` accepted and sent as Bearer; negative `expires_in`                                        | fixed `2a917d5`                                                        | quarantine table, `bearer_token_type_is_case_insensitive_test`                                                        |
| J13      | info       | `crit: null` accepted                                                                                             | fixed `ee413bc`                                                        | `null_crit_header_is_rejected_test`                                                                                   |
| C7       | low        | Reference app: cross-site POST to `/logout`                                                                       | fixed `dd10381`                                                        | `state_changing_requests_must_be_same_origin_test`                                                                    |
| C8       | low        | Reference app: anonymous `/client-token` spent client credentials                                                 | fixed `dd10381`                                                        | none (route now requires a session)                                                                                   |
| C10      | low        | Trust-anchor PEM accepted non-certificates and silently dropped keys                                              | fixed `3ac90f5`                                                        | `trust_anchors_must_all_be_certificates_test`                                                                         |
| C11      | low        | Explicit empty PKCE method list treated as omitted under the D7 opt-in                                            | fixed `69a4291`                                                        | `unadvertised_pkce_is_accepted_only_by_explicit_policy_test`                                                          |
| C13      | low        | Reference app sent no security headers                                                                            | fixed `dd10381`                                                        | `responses_carry_security_headers_test`                                                                               |
| T2       | low        | Cloud metadata addresses inside ranges `allow_private` admits                                                     | fixed `418d32b`                                                        | `classify_address_test`                                                                                               |
| T3       | low        | `ssl:send` had no deadline; request bodies unbounded                                                              | fixed `418d32b`                                                        | `large_request_bodies_are_refused_before_send_test`                                                                   |
| T4       | low        | Header limit missed the final read                                                                                | fixed `418d32b`                                                        | `header_limit_covers_the_final_read_test`                                                                             |
| T5       | low        | Close-delimited bodies cannot detect truncation (FIN without close_notify)                                        | accepted risk: a truncated JSON object or JWT fails to parse or verify | —                                                                                                                     |
| T6       | low        | IPv6 literal on port 443 sent an unbracketed Host header                                                          | fixed `02b83db`                                                        | `host_header_brackets_ipv6_literals_test`                                                                             |
| T7       | info       | Lenient response framing (bare LF, signed lengths)                                                                | fixed `02b83db`                                                        | `lenient_framing_is_refused_test`                                                                                     |
| T8       | info       | Teredo, ORCHID, benchmarking, 3fff::/20 classified public                                                         | fixed `418d32b`                                                        | `classify_address_test`                                                                                               |
| T9       | info       | `allowed_hosts` restricts hosts, not ports; no certificate revocation checking                                    | documented (application duty)                                          | —                                                                                                                     |

Unconfirmed and not filed: crash reports of the custody or transaction
actor could print queued messages carrying tokens; `sys:get_state` reveals
them. Covered by the VM-introspection duty in
[APPLICATION-RESPONSIBILITIES.md](APPLICATION-RESPONSIBILITIES.md).

## Owner decisions (2026-10-01)

- **F2 → D14:** absolute and idle session lifetime in configuration
  (`with_session_lifetime`, default 12 h / 1 h), measured on the monotonic
  clock, with expired sessions evicted (no capacity refusal).
- **J3 → D15:** a configurable clock tolerance (`with_clock_tolerance`,
  default 5 s) for `iat`, `nbf` and `auth_time`; `exp` stays strict.
- **F9:** fixed with the follow-ups (monotonic lifetimes).

## Deferred

- J10: refresh keys once on `bad_signature` when the token's `kid` matched no
  key (availability during rotation with kid-less keys).
