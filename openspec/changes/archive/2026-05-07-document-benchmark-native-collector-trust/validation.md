## Linux-Family Native Parity Validation

### Scope

- Validate Linux-family benchmark native collectors against maintenance-side system truth sources.
- Keep all command-based comparisons inside live tests and operator validation only.
- Do not reintroduce command execution into runtime benchmark collection.

### Current Status

- Windows native security-policy parity: completed in prior administrator validation.
- Linux native parity entry points: added for live validation in `internal/benchmark/unix_native_parity_live_test.go`.
- EulerOS native parity entry points: added for live validation in `internal/benchmark/unix_native_parity_live_test.go`.
- Kylin native parity entry points: pending live execution on matching hosts.

### Execution Log

- 2026-05-06: `go test ./internal/benchmark -run TestLoadBenchmarkRuleSet -count=1`
  - Result: pass
- 2026-05-06: `UNIX_BENCHMARK_LIVE=1 go test ./internal/benchmark -run TestLiveLinuxFamilyNativeCollectorsExposeRuleFields -count=1 -v`
  - Environment: Ubuntu 24.04.4 LTS on WSL2, root
  - Toolchain: local Linux Go 1.25.0 extracted from `C:\Users\Administrator\Downloads\go1.25.0.linux-amd64.tar.gz`
  - Result: pass
  - Verified live fields:
    - Linux: `pts_rule_absent`, `log_target_count`, `banner_configured`, `banner_content_present`
    - EulerOS-compatible path: `pts_rule_absent`, `access_control_present`, `banner_ok`
  - Remaining live coverage:
    - Kylin-specific live execution still requires Kylin host

### Validation Method

1. Run the current native collector path for the target Linux-family template and baseline level.
2. Compare rule-driving fields against platform truth semantics, not brittle raw string equality.
3. Treat maintenance-side commands only as validation sources, never as runtime fallback.

### Live Test Gate

- Environment variable: `UNIX_BENCHMARK_LIVE=1`
- Privilege requirement: root
- Current host coverage:
  - `linux`: runnable on Linux hosts such as Ubuntu/WSL
  - `euleros`: requires EulerOS/openEuler-compatible host
  - `kylin`: requires Kylin host

### Fields Verified First

- `pts_rule_absent`
- `log_target_count`
- `banner_configured`
- `banner_content_present`
- `access_control_present`
- `banner_ok`

These fields were prioritized because they directly drive rule evaluation and previously lacked explicit live parity coverage in Linux-family validation.
