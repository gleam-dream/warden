# Supply chain (gate V0)

Runtime dependencies (what an application using Warden installs). Warden
declares major-bounded ranges (D18); the versions below are the evidence
versions, which are also the declared lower bounds and the versions
`manifest.toml` locks:

| Package                                              | Version                           | Licence     | Source evidence                                                                                          | Advisories                                                               |
| ---------------------------------------------------- | --------------------------------- | ----------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| gose                                                 | 2.2.0 (Hex checksum `D46667C0A…`) | Apache-2.0  | Hex; upstream commit `961324d3`                                                                          | none in the GitHub Advisory Database (Hex ecosystem), checked 2026-10-01 |
| kryptos                                              | 1.5.0 (Hex checksum `0707A1492…`) | Apache-2.0  | Hex                                                                                                      | none found, 2026-10-01                                                   |
| bigi (via kryptos)                                   | 4.1.1                             | MIT         | Hex                                                                                                      | none found, 2026-10-01                                                   |
| exception                                            | 2.1.1                             | Apache-2.0  | Hex                                                                                                      | none found, 2026-10-01                                                   |
| gleam_crypto                                         | 1.6.0                             | Apache-2.0  | Hex                                                                                                      | none found, 2026-10-01                                                   |
| gleam_time                                           | 1.11.0                            | Apache-2.0  | Hex                                                                                                      | none found, 2026-10-01                                                   |
| telemetry                                            | 1.4.2                             | Apache-2.0  | Hex                                                                                                      | none found                                                               |
| http_gun                                             | 0.1.0                             | Apache-2.0  | unpublished; local path dependency on `gleam-dream/http_gun` (`369da4f` when adopted), D16               | none in the GitHub Advisory Database, checked 2026-10-01                 |
| gun (via http_gun)                                   | 2.6.0                             | ISC         | Hex                                                                                                      | all listed advisories are below 2.4.0, checked 2026-10-01                |
| cowlib (via http_gun)                                | 2.20.0                            | ISC         | Hex                                                                                                      | all listed advisories are at or below 2.16.1, checked 2026-10-01         |
| gleam_http                                           | 4.4.0                             | Apache-2.0  | Hex                                                                                                      | none found, 2026-10-01                                                   |
| file_streams / simplifile / filepath (via http_gun)  | 1.7.0 / 2.7.0 / 1.1.2             | Apache-2.0  | Hex                                                                                                      | none found, 2026-10-01                                                   |
| sinal                                                | 0.1.0                             | unpublished | local path dependency on `gleam-dream/sinal` (`44c5395`); needs a release before Warden can be published | not applicable                                                           |
| gleam_stdlib / gleam_erlang / gleam_otp / gleam_json | see `manifest.toml`               | Apache-2.0  | Hex                                                                                                      | none found                                                               |

The advisory query was checked against a control: it returns oidcc's
GHSA-mj35-2rgf-cv8p, but not GHSA-533g-4vf3-xwrj, so an empty result is
weak evidence and the release-time review still applies.

Test-only dependencies (`[dev-dependencies]`; not installed by applications):

| Package            | Version                              | Licence    | Source evidence                                                                                                                                                                                                                                                                                                                                                 | Advisories checked 2026-09-30                                                            |
| ------------------ | ------------------------------------ | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| oidcc              | 3.9.0 (Hex checksum `5A825092…41CE`) | Apache-2.0 | Hex `src/`+`include/` byte-identical to tag `v3.9.0` → commit `aa212d52d0140addf057c34917b734647401b34e`; annotated tag object `e5bad400ecb538bc0d826d54516fd7ee3b1cb2a8`; tag is PGP-signed (key `7D524A9B3F61C9428C54FDB10E52C3FCBFF3B295`, not verified locally: key not in keyring). Record definitions vendored into `test/integration/oidcc_records.hrl`. | GHSA-533g-4vf3-xwrj (high, `< 3.9.0`, fixed in 3.9.0); GHSA-mj35-2rgf-cv8p (fixed 3.0.2) |
| jose (erlang-jose) | 1.11.12                              | MIT        | Hex; signs the scripted provider's test tokens                                                                                                                                                                                                                                                                                                                  | GHSA-9mg4-v392-8j68 fixed in 1.11.7                                                      |
| telemetry_registry | 0.3.2                                | Apache-2.0 | Hex (oidcc requirement)                                                                                                                                                                                                                                                                                                                                         | none found                                                                               |

oidcc lists `igniter` as an optional (Elixir) requirement; it is not
downloaded or compiled.

Test-only assets: Keycloak image digest, node packages (`npm audit`: 0
vulnerabilities at install), OIDF conformance-suite images `release-v5.3.1`.
No production secrets or tenants are used; every key and credential is
generated per run or disposable.

A release SBOM and changelog review are release-time obligations (not
performed; no release is published).
