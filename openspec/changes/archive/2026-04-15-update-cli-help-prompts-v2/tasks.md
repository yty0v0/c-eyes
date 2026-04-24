## 1. Root And Standalone Risk Help Rewrite

- [x] 1.1 Rewrite `usage()` in `cmd/edr/unified_cli.go` to English `NAME/USAGE/DESCRIPTION/COMMANDS/GLOBAL OPTIONS` layout and use `-r, --riskanalyze` wording.
- [x] 1.2 Rewrite standalone risk help text in `parseRiskFlags` (`cmd/edr/main.go`) to English `NAME/USAGE/OPTIONS` layout while preserving one-of-five source constraints.

## 2. Hostscan/Filescan Consolidated Help

- [x] 2.1 Refactor `hostscanUsage(...)` and `filescanUsage(...)` to English `NAME/USAGE/OPTIONS` output and include `OPTIONS(only -r enable can use)` sections in base help pages.
- [x] 2.2 Adjust help-routing behavior so `edr hostscan -r -h` and `edr filescan -r -h` reuse consolidated base help output instead of separate risk-only pages.

## 3. Custom Module Help By Selection

- [x] 3.1 Implement `edr hostscan --custom <modules> -h` module-scoped OPTIONS output for single-module selection.
- [x] 3.2 Implement multi-module hostscan custom help that prints only intersection OPTIONS for selected modules.
- [x] 3.3 Implement `edr filescan --custom <modules> -h` module-scoped OPTIONS output for single-module selection and intersection OPTIONS for multi-module selection.

## 4. Tests And Verification

- [x] 4.1 Update/add tests in `cmd/edr/unified_cli_test.go` for English section headers, consolidated `-r -h` behavior, and custom module help output scopes.
- [x] 4.2 Update/add standalone risk-help assertions (including source exclusivity wording) in risk-related tests.
- [x] 4.3 Run targeted tests for CLI help/risk parsing and verify key commands: `edr -h`, `edr hostscan -h`, `edr hostscan -r -h`, `edr filescan -h`, `edr filescan -r -h`, and `edr -r -h`.

## 5. Explicit Selection And Progress Restore

- [x] 5.1 Enforce explicit execution-mode selection in unified CLI (`hostscan` requires `--all/--custom`; `filescan` requires `--all/--custom/--scan-mode`) and align error wording with parser behavior.
- [x] 5.2 Update `hostscan/filescan -h` option prompts to fully state mutual-exclusion relationships among `--all`, `--custom`, and `--scan-mode` (filescan).
- [x] 5.3 Restore terminal progress display for unified `hostscan/filescan` execution paths by wiring module/local scan `Progress` callbacks and adding scoped-progress regression tests.
