# Changelog

## Unreleased

- Provide independent relying-party, confidential service-client and resource-server roles through typed configuration.
- Implement discovery/key caching, code login with S256/state/nonce, strict ID-token validation and checked identity using native Gleam over gose/kryptos.
- Use HTTP Gun for destination-aware verified HTTPS, bounded provider requests and typed transmission evidence; expose redacted Sinal observations with caller correlation.
- Bind browser callbacks through owned response helpers and support exact admitted per-login redirects.
- Provide sealed CAS-backed pending transactions and user-token custody with durable adapters, key rotation, lifetime policy and publication recovery.
- Coordinate rotating refresh, quarantine uncertain effects, reuse confirmed current token generations and prevent provider resend during recovery.
- Provide subject-checked userinfo, service grants, introspection, local JWT resource validation, token revocation and RP-initiated logout.
- Provide a public scripted HTTPS test issuer, including per-subject optional email assertions and runtime updates, test PKI, CAS conformance check, compiled consumers and independent provider/oracle harnesses.
- Own each cache fetch by its actual incarnation and join old client children under the startup deadline before name reuse. Every replacement cache starts with fresh discovery.
- Publish the native design, canonical vocabulary, consumer responsibilities and ADR rationale. Full later protocol intent and unresolved authority/evidence requirements remain explicit.

Decision provenance and alternatives are in [docs/adr](docs/adr/0010-native-documentation-ownership.md). Runtime release conditions are in the [design layer](docs/design/design.typ) and [testing guide](docs/TESTING.md).
