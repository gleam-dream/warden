# Provider transport composes HTTP Gun with Warden policy

<a id="adr-0002"></a>

- **Decision:** each Warden client owns a supervised HTTP Gun pool. HTTP Gun owns DNS/address policy, verified TLS, framing and connection lifetime. Warden retains HTTPS-only endpoint/header hygiene, request/body bounds, content-encoding refusal and secret-safe failure mapping.
- **History:** D2 originally rejected default httpc and HTTP Gun without pre-connection destination control. D11 first moved the owned transport to Gleam, then adopted HTTP Gun in `55a493b` on 2026-10-01 after its destination/trust/readiness gaps were fixed. D34 retained HTTP Gun's separate connect, checkout and idle bounds.
- **Alternatives:** an independent socket/parser duplicated substantial correctness machinery. Default adapters lacked pre-allocation bounds or destination policy. Reusing HTTP Gun became viable once its public port could enforce those invariants.
- **Accepted limitations:** D17 retained ReceiveFailed for truncated fixed body, invalid status, signed content length and signed chunk size when Gun only exposed close/crash. A bare LF in discarded reason text may be accepted on a close-delimited connection. Diagnostics are coarser; uncertainty remains possible-send. Close-delimited TLS truncation cannot prove complete provider data, which still must parse or verify.
- **Evidence limits:** original isolation logs contain failures that preceded adoption. They are raw receipts, not current open rejection reports. IPv6 default-port binding was not probed there. Exact detailed historical tables remain available at their immutable revision.
- **Provenance:** [D2/D11/D17/D34](https://github.com/gleam-dream/warden/blob/f3847d102c0db9f66e4d4a72a9c7b3028507c7ac/docs/decisions.md); [original adoption report](https://github.com/gleam-dream/warden/blob/f3847d102c0db9f66e4d4a72a9c7b3028507c7ac/docs/evidence/http-gun-adoption/README.md). Retained `transport.gleam`, transport/pool tests and `docs/evidence/http-gun-adoption/logs/`.
- **Dependency policy:** D16 temporarily permits unpublished sibling paths; D18 chose major-bounded runtime ranges over exact library-wide pins to allow composition. `manifest.toml` locks tested resolutions; test oracles remain exact. Publication requires released sibling dependency declarations and renewed suite evidence.

## Adoption receipt provenance

- The isolated 1 October 2026 experiment used HTTP Gun `369da4ffc2671c1dbc63e1ecd1355e8ca42e403e`, Sinal `8acec4507f23daa7f49c40cc7d39816a5a4c3d1d` and Warden `230c6bb`, with the node test correction described in the immutable report above. It retained Darwin ARM64/OTP output from transport/pool, framing/bounds, security and local provider checks. Its temporary adapter/probes were removed after the public port was adopted.
- Raw logs remain in `docs/evidence/http-gun-adoption/logs/`. Inherited HTTP Gun matrices, H2/load results and other consumers were not rerun by this experiment and did not independently establish Warden compatibility. The old script paths and measured results are historical evidence, not current operating commands.
