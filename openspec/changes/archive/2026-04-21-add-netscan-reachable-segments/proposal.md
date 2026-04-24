## Why

The current `netscan` default behavior is intentionally conservative and only scans the primary interface C-segment when no target is provided. In real enterprise networks with routed private subnets, this misses reachable assets unless operators manually provide targets, so we need an explicit, bounded way to discover cross-segment reachability.

## What Changes

- Add an opt-in execute option to `c-eyes netscan` that enables reachable-segment discovery without changing existing default behavior.
- Define deterministic candidate-segment discovery from local routing visibility and existing local connection facts (collection-only, no risk-analysis chaining).
- Define a lightweight gateway-oriented active verification step to confirm routed segment reachability before expanding probe targets.
- Define strict safety controls for this mode, including private-address scope, bounded candidate expansion, and continued enforcement of `maxTargets`.
- Extend normalized metrics/output semantics to expose reachable-segment discovery evidence and execution summary for operator auditability.
- Update `netscan` help text so the new option and its behavior are visible in `EXECUTE OPTIONS`.

## Capabilities

### New Capabilities
- None.

### Modified Capabilities
- `netscan-scan`: Add optional cross-segment reachable discovery workflow, target expansion rules, and output/metrics semantics while preserving default primary-interface behavior.
- `cli-help-prompts`: Update `netscan` help requirements to include the new reachable-segment execute option and behavior notes.

## Impact

- Affected code:
  - `cmd/edr/unified_cli.go` (new netscan execute flag parsing, help text, progress/info messaging)
  - `internal/netscan/types.go` (new execute parameter and metrics/result fields)
  - `internal/netscan/targets.go` plus new routing/connection discovery helpers (candidate segment resolution and bounded expansion)
  - `internal/netscan/scan.go` and probe orchestration for reachable-segment verification flow
  - `cmd/edr/unified_cli_test.go` and `internal/netscan/*_test.go` for argument, behavior, and safety-limit coverage
- Affected specs:
  - Modified delta: `openspec/changes/add-netscan-reachable-segments/specs/netscan-scan/spec.md`
  - Modified delta: `openspec/changes/add-netscan-reachable-segments/specs/cli-help-prompts/spec.md`
- Dependencies/systems:
  - Continue using in-process OS APIs and standard library primitives (no shell-command-based collection)
  - Continue using existing global output pipeline (`-o`) and adaptive throttling model
