# Keep PostgreSQL configuration opaque

<a id="adr-0014"></a>

## Decision

The optional PostgreSQL adapter exposes an opaque `Config`, constructed with
`config(pool)` and composed with `with_schema` and `with_timeouts`. Construction
and settings remain pure; `new` validates the complete value before initialization
or record operations can perform database work.

## Rationale and consequences

The initial adapter exposed its configuration record constructor. Consumers could
therefore depend on its complete representation, making future defaulted settings
a source compatibility change. Opaque configuration follows the ecosystem's
[caller contract](https://github.com/gleam-dream/oversight/blob/main/docs/adr/0002-preserve-caller-owned-values-and-decisions.md).

Schema and server time limits remain explicit caller choices. The adapter still
borrows the caller's named pool, and its timeout settings do not replace Warden's
store deadline or establish shutdown completion. No validation or storage outcome
is weakened. Unreleased consumers using record construction must migrate to the
setters.

## Evidence

A separate consumer compiler fixture rejects direct construction, with a positive
public-path control. The existing PostgreSQL consumer suite exercises default and
advanced settings, invalid configuration without a running pool, conditional
writes and Warden recovery through the public API.

Accepted during the ecosystem contribution review on 13 October 2026.
