## Why

Recent optimization work improved scan speed by introducing adaptive concurrency in multiple execution paths, but these behavior-level changes were not recorded in OpenSpec. We need the spec to document the new runtime contract so future changes preserve both performance and result correctness.

## What Changes

- Document adaptive module concurrency for unified `hostscan` execution based on runtime CPU/memory pressure and queue backlog.
- Document adaptive module concurrency for unified web-mode `filescan` execution with the same runtime signals and bounded worker ranges.
- Document mode-aware adaptive concurrency for local `filescan --scan-mode` pipeline execution (`full`, `path`, `smart`) and periodic runtime tuning.
- Document that local `filescan` no longer accepts `--workers` and now treats concurrency as automatic runtime behavior.
- Document that performance tuning must preserve result-set equivalence (no record-loss contract changes) for the same static input snapshot.

## Capabilities

### New Capabilities
- (none)

### Modified Capabilities
- `hostscan`: Add explicit requirement for adaptive module concurrency behavior and safety bounds.
- `filescan`: Add explicit requirements for adaptive web-module concurrency and local `--workers` rejection behavior.
- `file-scan`: Add explicit requirement for mode-aware adaptive local pipeline concurrency and dynamic tuning loop behavior.

## Impact

- Affected CLI/runtime orchestration in `cmd/edr/unified_cli.go` for hostscan/filescan web module scheduling.
- Affected local file scan pipeline execution profile selection in `internal/filescan/pipeline.go` and mode propagation in `internal/filescan/scan.go`.
- Affected tests for concurrency profile selection and adaptive behavior guardrails.
- No new external dependency, protocol, or output schema change is introduced.
