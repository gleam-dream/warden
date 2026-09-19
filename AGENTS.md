# Agent Instructions

## About this repo

`warden` — A typed Gleam OIDC / OAuth 2.0 Relying Party, built on the certified oidcc backend via FFI.

Ports/wraps: oidcc (erlef/oidcc). Design: [gleam-dream/oversight](https://github.com/gleam-dream/oversight)/warden-design.md.

## Tooling

- `nix develop` (or direnv): dev shell with `gleam`, Erlang/OTP 28, `rebar3`, `lefthook`.
- `nix fmt`: formats the whole repo via treefmt (`gleam format`, `nixfmt`, `prettier`).
- `lefthook`: pre-commit hook formats staged files and re-stages them.
- `nix flake check`: fails iff the tree is not formatted (plus any existing checks).
- `gleam test`: runs the test suite.
