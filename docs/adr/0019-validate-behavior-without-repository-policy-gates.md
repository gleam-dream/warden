<a id="adr-0019"></a>

# 0019: Validate behavior without repository-policy gates

Date: 2026-10-20
Status: Accepted

## Decision

Required validation uses the shared formatter and compiler, unit tests, integration tests and the imported design-layer check. CI invokes `nix flake check` and `nix run .#design-gate-check -- docs/design .` directly. Public consumer and compiler-negative tests remain because they exercise callable contracts. Native compilation and synchronized runtime probes remain where Gleam unit tests cannot establish the behavior.

Remove README equality, documentation-header, source-layout and dependency-policy audits; checker self-tests; tooling lint and custom evidence acceptance requirements. Keep process exit failures, fixture cleanup, isolated consumers and credential-free local execution. Benchmark observations are optional and impose no performance threshold.

This supersedes the validation-policy and evidence-machinery requirements in ADRs 0010, 0015 and 0016, while preserving their product behavior and historical observations. Design rendering and context export use the imported design-layer tools; no repository-local checker wraps them.

## Consequences

Reviewers own documentation consistency and architectural conventions. Tests no longer reject harmless source rearrangements. Direct command lists have less self-testing and receipt metadata; normal command output and CI logs establish what ran. Runtime tests and public-contract compilation continue to reject observable regressions.
