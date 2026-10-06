# OIDC policy stays explicit and stricter than permissive defaults

<a id="adr-0003"></a>

- **Decision:** Warden selects authentication and asymmetric signing policy explicitly, requires S256 and nonce, and accepts singleton client audience at login. A token/header/metadata field cannot enlarge configuration authority. Login requires an ID token even where an oracle accepts its absence.
- **History:** D3 narrowed oidcc's automatic PAR/JAR, plain PKCE fallback, metadata-driven auth and permissive audience behavior. Native orchestration removed that adapter machinery while preserving the requirements.
- **PKCE exception:** owner D7 on 2026-09-30 (`9d74e20`) permits `AssumeS256WhenUnadvertised` only for confidential clients and metadata omission. An explicit list without S256 still fails. The local conformance OP omitted the field; an implicit test bypass was rejected in favor of a public explicit trust decision.
- **Consequence:** verifier/challenge, state and nonce remain unchanged. An issuer that ignores PKCE weakens intercepted-code protection; confidential credentials and nonce remain separate barriers. Public clients cannot use the exception. Transport authentication prevents a network intermediary silently stripping discovery metadata.
- **Redirect policy:** D36/D37 (`1e507d4`, 2026-10-03) chose immutable exact per-login allowlists over mutable redirect configuration. The deployment address is known before Client creation; ephemeral listener ordering belongs to the test harness. Normalization, wildcard and prefix matching were rejected.
- **Key anchors:** D39 declined a JWK/JWKS trust anchor because TLS certificate format conversion did not establish an offline signing-key requirement. Bypassing JWKS discovery/rotation would add custody and rotation risk. Revisit only for an actual offline/provider requirement.
- **Provenance:** [D3/D7/D36/D37/D39](https://github.com/gleam-dream/warden/blob/f3847d102c0db9f66e4d4a72a9c7b3028507c7ac/docs/decisions.md); retained config, JOSE, key-strength and redirect/PKCE tests. Historical signatures in migration guides are not the current facade.
