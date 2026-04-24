## Why

Recent CLI refinements improved detection and operator feedback, but those behavior changes are not yet captured in OpenSpec.  
We need to document the final contracts now so runtime behavior, tests, and future refactors remain aligned.

## What Changes

- Document risk-analysis streaming output behavior for chained and standalone runs:
  - print risky findings as they are produced,
  - use severity bands (`HIGH`, `MEDIUM`, `LOW`) with terminal color when supported,
  - print a final risk summary with non-zero band counts.
- Document risk-analysis progress behavior in mixed log output terminals:
  - keep one visible risk progress row,
  - avoid multi-line corruption by using stable single-line redraw behavior,
  - throttle progress refresh cadence to reduce visual noise.
- Document filescan/local file collection permission behavior:
  - path-mode root access denial returns explicit access-denied error,
  - collection-stage permission denials are reported per inaccessible entry and do not abort the entire scan.
- Document project whitelist policy behavior updates:
  - project hash baseline whitelist is enabled by default,
  - explicit environment switches can disable/override root and baseline path,
  - setup warnings are emitted only on failures.

## Capabilities

### New Capabilities
- None.

### Modified Capabilities
- `risk-analysis`: terminal streaming, severity-colored output, summary, and stable single-row progress behavior.
- `filescan`: chained risk runtime output contract and local-mode permission feedback behavior.
- `file-scan`: local path collection permission handling and error reporting contract.
- `risk-whitelist-policy`: default-on project baseline whitelist setup and override semantics.

## Impact

- Affected code paths:
  - `cmd/edr/unified_cli.go`
  - `cmd/edr/main.go`
  - `cmd/edr/progress.go`
  - `cmd/edr/project_whitelist.go`
  - `internal/filescan/scan.go`
  - `internal/filescan/collectors.go`
  - `internal/riskanalysis/analyzer.go`
- Affected tests:
  - `cmd/edr/unified_cli_test.go`
  - `cmd/edr/project_whitelist_test.go`
  - `internal/filescan/scan_path_access_test.go`
  - `internal/filescan/collectors_permission_test.go`
- No API endpoint changes; behavior changes are CLI/runtime contract and spec-level output/diagnostic semantics.
