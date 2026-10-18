# Agent Instructions

## About this repo

`warden` — a typed Gleam OIDC / OAuth 2.0 relying party on gose (JOSE), with HTTPS on HTTP Gun. oidcc 3.9.0 is a test-only oracle.

- Read `docs/design/design.typ`, `docs/design/CONTEXT.typ` and `docs/COVERAGE.md` before changing a public boundary.
- Preserve intended protocol capabilities and unresolved authority and evidence obligations. Recording a gap does not resolve it.

## Tooling

- `nix develop` (or direnv): dev shell with `gleam`, Erlang/OTP 29, `rebar3`, `lefthook`.
- `nix fmt`: formats the whole repo via treefmt (`gleam format`, `nixfmt`, `prettier`).
- `lefthook`: pre-commit hook formats staged files and re-stages them.
- `nix flake check`: fails iff the tree is not formatted (plus any existing checks).
- Unpublished sibling packages (Sinal, HTTP Gun, Relay, JSON Blueprint) are Git dependencies with `ref = "main"`, and each `manifest.toml` is the lock. Update one by hand with `gleam update <package>`; no workflow or script moves a dependency (ADR 0015).

## Gates and tests

- `nix develop -c scripts/check`: canonical fast gate (formatting, build warnings, local tests, negative compiler fixtures, both consumers, Relay recipe, PostgreSQL adapter, design gate). It needs no provider container or external issuer.
- `nix develop -c scripts/check full`: adds the node, keycloak, interop and browser provider suites. It needs Docker Compose and Google Chrome.
- Fresh root build on OTP 29: run `ERL_COMPILER_OPTIONS='[nowarn_deprecated_catch]' gleam build --warnings-as-errors`, then `scripts/erlang-check`, then `WARDEN_SUITE=fast gleam test`. Never export the option in the shell (ADR 0016).
- Provider suites: `scripts/keycloak up`, `scripts/node-provider up`, `scripts/interop up` or `scripts/conformance-suite up`, then `WARDEN_SUITE=keycloak|node|interop gleam test`, `scripts/browser-journey` or `scripts/conformance`. Stop each fixture with its `down` command. A stale `build/node-provider.owner` or `build/hydra-consent.owner` directory is removed by hand only after inspection.
- OpenID plans: `WARDEN_CONFORMANCE_POLICY=regression scripts/conformance-check basic,formpost,config,refresh,logout`.
- `scripts/postgres-check` and `scripts/postgres-negative` run the PostgreSQL adapter against a temporary cluster. `scripts/relay-recipe` compiles the README Relay recipe and compares it with the `warden/resource` module doc.
- `scripts/benchmark` produces observations only (ADR 0017). Ports 8443 and 19443 must be free for the conformance-driver and fixture-lifecycle gate checks.
- Usage lives as compiled examples in `consumer/src/warden_reference/usage/`, run by `consumer/test/usage_test.gleam` inside `scripts/check`. `python3 -B scripts/check-doc-examples.py` fails when a README block differs from its marked `// docs:begin NAME` region. Change an example and its README block together; add no prose usage guide.
- After editing design sources or ADRs, run the design-gate commands in the block below.

## References

- [`docs/ORACLE.md`](docs/ORACLE.md) pins the independent references Warden is compared with (OpenID Foundation RP suite `release-v5.3.1`, Keycloak, node-oidc-provider, Dex, Hydra, test-only oidcc and erlang-jose), what each comparison establishes and how to rerun it. Update it when a pin, fixture or result changes.
- [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) retains the local measurements of provider cache cost, their method and limits. It links back to `docs/ORACLE.md`; a benchmark never gates a change.

<!-- agent-skills:begin -->
<!-- framework-commit: cab7c0590036edaa66d8430cc5016399a9fd2c71 origin: git@github.com:lostbean/skills.git -->

(machine-owned; do not edit inside this fence — re-run setup to refresh)

## Agent skills

**Design layer** — `docs/design/design.typ` describes the design,
`docs/design/CONTEXT.typ` defines its vocabulary, and `docs/adr/` records
decision rationale. The rendered document is `docs/design/design-layer.pdf`.
`docs/COVERAGE.md` maps repository parts to their design owners.

**Tracker** — local markdown under `issues/`: one directory per feature
(`issues/<feature-slug>/`), the PRD at `issues/<feature-slug>/PRD.md`, issue
files at `issues/<feature-slug>/issues/<NN>-<slug>.md` numbered from 01. Each
issue file carries two header lines near the top — `Status: <state>`,
`Category: <category>`. Conversation appends to the bottom
of the file under a `## Comments` heading. Labels (canonical strings, adopted
verbatim): states `needs-triage`, `needs-info`, `ready-for-agent`,
`ready-for-human`, `in-progress`, `done`, `wontfix`; categories `bug`,
`enhancement`.

**AI disclaimer** — AI-authored tracker comments start with
`AI-assisted contribution.`

**Design gate** — `nix run .#design-gate-check -- docs/design .` checks render freshness,
vocabulary references and layer integrity (exit 0 clean, 1 violation, 2 error).
The gate is supplied by the pinned `design-layer` flake input.
`nix run .#design-gate-render -- docs/design docs/design/design-layer.pdf`
rebuilds the rendered document. `nix run .#design-gate-context -- docs/design --estimate`
estimates agent context; the same command without `--estimate` emits ephemeral
Markdown. `--manifest`, `--preview`, and `--section PATH --expect-digest DIGEST`
support loading selected sections. A bare Typst compilation does not run the gate.

**Context verification** — use native semantic blocks for lists, tables,
models and behavior. After authoring, verify context estimation and a selected
section export as well as rendering and the design gate.
Run these commands sequentially for each layer; they share its generated
`.render` workspace.

**Staleness** — source changes since the design last changed require a
conformance review before the layer is treated as current.

<!-- agent-skills:end -->
