## Why

The current CLI help output is still partly mixed between legacy Chinese examples and new unified behavior, which causes confusion for users who expect a consistent English help surface. We need a single, code-aligned help redesign that matches the new documentation plan in `docs/change3.md`.

## What Changes

- Rewrite root help (`edr -h`) to an English structured template (`NAME/USAGE/DESCRIPTION/COMMANDS/GLOBAL OPTIONS`) with command discovery focused on `hostscan` and `filescan`.
- Rewrite `edr hostscan -h` and `edr filescan -h` into English option-oriented help, including risk-analysis option sections in these pages.
- Consolidate risk guidance by removing dedicated `edr hostscan -r -h` and `edr filescan -r -h` help pages and relying on `hostscan -h` / `filescan -h` for those prompts.
- Rewrite standalone risk help (`edr -r -h`) to English and keep one-of-five source constraints explicit.
- Align module-selection behavior with current parser logic:
  - `edr hostscan` must explicitly provide one of `--all` or `--custom`.
  - `edr filescan` must explicitly provide one of `--all`, `--custom`, or `--scan-mode`.
- Update `hostscan/filescan -h` prompts to explicitly describe mutual-exclusion relationships among `--all`, `--custom`, and `--scan-mode` (filescan).
- Restore terminal scan progress display in unified CLI execution paths for `hostscan` and `filescan` (including filescan local mode).
- Keep behavior aligned with existing code logic, including supported global long flag `--riskanalyze` and current parameter model.
- Update tests that assert help text and usage-routing behavior to match the new prompts.
- Add regression tests for progress-scoping output formatting used by unified hostscan/filescan execution.

## Capabilities

### New Capabilities
- None.

### Modified Capabilities
- `cli-help-prompts`: Root help template and global help wording are replaced with English structured output.
- `hostscan`: Help behavior integrates risk option guidance into `hostscan -h`; runtime now requires explicit module-selection mode (`--all` or `--custom`) and shows terminal progress during scanning.
- `filescan`: Help behavior integrates risk option guidance into `filescan -h`; runtime now requires explicit execution mode (`--all`/`--custom`/`--scan-mode`) and shows terminal progress during scanning.
- `risk-analysis`: Standalone risk help text is rewritten in English while preserving current source/risk parameter constraints.

## Impact

- Affected code:
  - `cmd/edr/unified_cli.go`
  - `cmd/edr/main.go`
  - `cmd/edr/unified_cli_test.go`
  - `cmd/edr/progress_test.go`
  - `cmd/edr/risk_flags_test.go` (if risk-help assertions need updates)
- User-facing impact:
  - Help prompts become English-first and structurally consistent.
  - `hostscan/filescan` risk help entry points are consolidated into base help pages.
  - `hostscan/filescan` no longer implicitly default to web/all-module mode in unified CLI; users must choose explicit mode flags.
  - Unified CLI scan commands again display terminal progress rows while scanning.
