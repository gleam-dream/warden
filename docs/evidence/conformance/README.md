# OpenID RP conformance evidence (local, not certification)

- Suite: OpenID Foundation conformance suite `release-v5.3.1` (prebuilt
  images, dev mode), run locally on 2026-10-01 against the final tree (gose
  backend only) with verified TLS (suite certificate from the disposable
  test CA). Evidence: `run-log.txt`, `summary.json`.
- RP: `consumer/` reference RP (public Warden API), one fresh process per
  module, static client, `client_secret_basic`, plain HTTP request.
- **Policy label:** every result below was produced with the non-default
  opt-in `AssumeS256WhenUnadvertised` (decision D7), because the suite's OP
  does not advertise `code_challenge_methods_supported` and Warden's default
  policy refuses such providers. Warden still sent and checked its own S256
  challenge and nonce.
- Driver: `test/conformance/run.mjs` (`scripts/conformance`). Module logs are
  written to `build/conformance/` (not committed; regenerate with the command).

`history/` keeps the 2026-09-30 runs of the removed oidcc backend (decision
D13). They gave the same verdict for every module; they predate the public
D7 opt-in and used the equivalent internal harness entry point.

| Plan                                                | PASSED | SKIPPED | REVIEW | FAILED / not run |
| --------------------------------------------------- | -----: | ------: | -----: | ---------------- |
| oidcc-client-basic-certification-test-plan          |     13 |       1 |      0 | 0                |
| oidcc-client-formpost-basic-certification-test-plan |     13 |       1 |      0 | 0                |
| oidcc-client-config-certification-test-plan         |      5 |       1 |      0 | 0                |
| oidcc-client-refreshtoken-test-plan                 |      3 |       0 |      0 | 0 (see note)     |
| oidcc-client-rp-initiated-logout-rp-basic           |      0 |       0 |      3 | 0                |
| oidcc-client-test-3rd-party-init-login-test-plan    |      0 |       0 |      0 | 1 (suite defect) |

Notes:

- SKIPPED rows are `oidcc-client-test-idtoken-sig-none`: Warden rejects
  `alg: none`, which the suite scores as SKIPPED. They are not passes.
- REVIEW: the RP-initiated logout requests were accepted and the suite
  redirected back with `state` (or without, as the module intends), but the
  suite requires human review of the front-channel step. Warden does not
  implement front-channel logout (explicit gap); the reference RP's
  `/frontchannel-logout` route is a declared stub. Not counted as passes.
- Third-party initiated login: the module interrupts itself during setup
  (`Illegal test state change: CREATED -> RUNNING`) before any RP request,
  reproduced with no RP running (`build/probe-3rd.mjs`). Infrastructure gap;
  the reference RP's `/initiate-login` route remains unverified by the suite.
- All plans ran in one consolidated pass. (In the first oidcc-backend run,
  `oidcc-client-test-refresh-token-invalid-issuer` had to be rerun alone
  because the previous RP still held the port; the driver now waits for RP
  exit.)
- Local results are regression evidence only; certification requires a
  hosted submission for an exact Warden release.
