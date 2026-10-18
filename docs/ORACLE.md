# Warden oracles

Warden is compared with independent references so that its own tests are not the
only authority. This document names each reference, the revision it is pinned to,
what the comparison establishes, how to run it and where the claim stops. The
design's [validation gates](design/design.typ) section owns the obligations,
[ADR 0008](adr/0008-oracles-and-evidence-limits.md) records the interpretation of
the retained receipts, and [BENCHMARKS.md](BENCHMARKS.md) holds the measurements,
which use the same local provider fixtures. Agent commands are in
[`AGENTS.md`](../AGENTS.md).

A match is bounded to its case and revision. It does not prove compatibility with
an arbitrary provider, cryptographic safety, or certification. A local receipt is
regression evidence only; an older receipt never qualifies a new dependency
resolution or fixture pin.

## References

| Reference                              | Role                                                                                                | Upstream                                          | Pin                                                                                                                                                                                                        |
| -------------------------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OpenID Foundation RP conformance suite | Selected relying-party plans (Basic, Config, Form Post, refresh, RP logout, third-party initiation) | <https://gitlab.com/openid/conformance-suite>     | `release-v5.3.1`, revision `440eec8bac7b12b7389d7ca9cbc459b53507a443` (MIT); compose pins in `test/conformance/`                                                                                           |
| oidcc (test-only)                      | Differential oracle for protocol decisions                                                          | <https://github.com/erlef/oidcc>                  | `== 3.9.0`; tag `v3.9.0` at `aa212d52d0140addf057c34917b734647401b34e`, annotated tag `e5bad400ecb538bc0d826d54516fd7ee3b1cb2a8` (Apache-2.0); record declarations in `test/integration/oidcc_records.hrl` |
| oidcc conformance harness              | Upstream harness the differential corpus follows                                                    | upstream location not retained in this repository | revision `b632d9745b9490229ebca004b4df9928e1457d51` (Apache-2.0)                                                                                                                                           |
| Keycloak                               | Browser login, races, rotating refresh, revoked sessions                                            | <https://www.keycloak.org>                        | `quay.io/keycloak/keycloak:26.7.5`, digest `sha256:37dbaf6f0722c9ec246335f36e1ef8b2e6cb960f7c27e0d8c615121a3d475a85`                                                                                       |
| node-oidc-provider                     | Scriptable provider: forged and changed claims, transport cases, comparison with oidcc              | <https://github.com/panva/node-oidc-provider>     | `oidc-provider` 9.12.2 with `jose` 6.2.12 (lock: `test/providers/node-oidc/package-lock.json`)                                                                                                             |
| Dex                                    | Particular interoperability contract                                                                | <https://github.com/dexidp/dex>                   | `ghcr.io/dexidp/dex:v2.45.1@sha256:8499afd690c437f52301efd2b05b2455da5bd2dfc20332cd697dc9937f808462`                                                                                                       |
| Hydra                                  | Particular interoperability contract                                                                | <https://github.com/ory/hydra>                    | `oryd/hydra:v26.2.0@sha256:ff67c7fb5f95074fa53374d41151713554960504b340cd3f95b09e65deaea2a9`                                                                                                               |
| erlang-jose (test-only)                | Signs the scripted test provider's tokens                                                           | <https://github.com/potatosalad/erlang-jose>      | `== 1.11.12`; frozen, unary `catch` kept (ADR 0016)                                                                                                                                                        |
| JOSE vectors                           | Token and key parsing                                                                               | RFC 7515, 7517, 7520; Project Wycheproof          | vectors retained under `test/`                                                                                                                                                                             |

Runtime JOSE is gose and kryptos and runtime HTTPS is HTTP Gun. oidcc, erlang-jose
and telemetry_registry are development oracles; an application does not install
them by using Warden.

No upstream oracle input is committed except one header. `scripts/conformance-suite`
fetches the suite's `docker-compose-prebuilt.yml` at tag `release-v5.3.1` from
<https://gitlab.com/openid/conformance-suite/-/raw/release-v5.3.1/docker-compose-prebuilt.yml>
into `build/oracle-inputs/` and stops unless its sha256 is
`c80e417b2a0c735e595dd49e6cd95fc43a75b692389016ddb863c4539e41d330`. The
oidcc 3.9.0 record declarations that the raw probes compile against stay in
`test/integration/oidcc_records.hrl`. Every project that depends on Warden by
path compiles those probes without the oidcc development dependency, so an
`-include_lib` of oidcc's own headers would force oidcc and its JOSE oracle
into each consumer. Container images are pulled by the digests above.

## What each comparison establishes

| Comparison         | Classification of outcomes                                                                                                                                          | Establishes                                                               |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| OpenID RP plans    | `PASSED` is a pass. `SKIPPED` and `REVIEW` are non-pass and stay distinct; interruption, unknown outcomes, driver errors, missing modules and empty selections fail | Regression of selected modules against the retained suite release         |
| oidcc differential | A difference is either recorded (stricter audience, required ID token, refresh handling) or fails the run                                                           | Agreement on the compared cases at the pinned oidcc revision              |
| Keycloak           | Pass or fail per scenario; logs and browser journey JSON retained                                                                                                   | Browser login, races, rotating refresh and revoked sessions on this image |
| node-oidc-provider | Forged and changed claims and transport cases are refused or accepted as recorded; compared with oidcc                                                              | Claim and transport handling against a scriptable independent provider    |
| Dex and Hydra      | Pass or fail per scenario                                                                                                                                           | Their particular interoperability contracts                               |

OpenID verdicts default to strict: every selected module must finish `PASSED`.
`regression` mode (`WARDEN_CONFORMANCE_POLICY=regression`) permits only the exact
`SKIPPED` unsigned-token and `REVIEW` logout outcomes listed in
`test/conformance/known-outcomes.json`; they remain non-pass evidence. Neither
policy confers certification.

## Exclusions and deliberate differences

- The 2026-10-01 local runs used the non-default confidential-client option
  `AssumeS256WhenUnadvertised`, because the suite's test provider omits PKCE
  metadata. Unsigned-token modules were skipped because Warden refuses `none`.
  RP logout modules required human review. Third-party initiation stopped in suite
  setup before any relying-party request. None of these is promoted to a pass.
- Warden is deliberately stricter than the oracle in three recorded cases: exact
  access-token audience, a required ID token, and refresh handling. These
  differences are the expected outcome, not failures.
- The advisory-query control found oidcc `GHSA-mj35-2rgf-cv8p` but missed
  `GHSA-533g-4vf3-xwrj`, so an empty advisory query is weak evidence. The oidcc
  tag signature was not verified locally because its key was absent.
- Kid-less wrong-key rotation may not refetch, `allowed_hosts` does not restrict
  ports, and certificate revocation checking is not claimed.

## Run a comparison

All fixtures are disposable and local; no public issuer or production tenant is
used. `scripts/test-pki` generates the test PKI under `build/test-pki`.

```sh
scripts/keycloak up && WARDEN_SUITE=keycloak gleam test
scripts/node-provider up && WARDEN_SUITE=node gleam test
scripts/interop up && WARDEN_SUITE=interop gleam test
scripts/browser-journey
scripts/conformance-suite up
WARDEN_CONFORMANCE_POLICY=regression scripts/conformance-check basic,formpost,config,refresh,logout
```

`scripts/provider-check node|keycloak|interop|browser` runs a suite and stops its
fixture. Stop a fixture with its `down` command. Node provider and Hydra consent
startup refuse an occupied port or an existing ownership record; after an
uncatchable fixture death, inspect and remove the stale `build/*.owner` directory by
hand. The full gate (`scripts/check full`) runs all four provider suites and needs
Docker Compose and Google Chrome. Ports 8443 and 19443 must be free for the
conformance-driver and fixture-lifecycle gate checks.

## Receipts

| Receipt                                                   | Contents                                                      |
| --------------------------------------------------------- | ------------------------------------------------------------- |
| [`evidence/conformance/`](evidence/conformance/README.md) | `summary.json`, the outcomes of the native backend's last run |

The conformance run log, the removed backend's receipts, the browser journey
receipts and the raw logs of the HTTP Gun adoption experiment (ADR 0002) are
retained in repository history at commit `afd4f25`.

Retain a new result with the exact package, fixture, option and toolchain
revisions, and keep skipped and human-review modules separate from passes. Never
overwrite checked-in history. The retained 1 October 2026 conformance summary
recorded Basic and Form Post at 13 passed and one skipped each, Config at five
passed and one skipped, refresh at three passed and RP logout at three
review-needed modules.

## Limits of the claim

A conformance or differential result does not establish security, certification or
provider compatibility beyond its case. Races, unknown store effects, provider
uncertainty, expiry barriers, process replacement and redaction need the runtime
evidence the design names. Release acceptance also requires changed dependency and
advisory review, a release SBOM and independent review of Warden-owned security
code (ADR 0008).
