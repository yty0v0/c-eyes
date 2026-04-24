## Context

The CLI is already unified under `runUnifiedCLI`, but help output is currently split across multiple patterns:
- root help is example-driven and Chinese,
- `hostscan/filescan` risk guidance is partly behind `-r -h`,
- module help for `--custom` is single-module friendly but not designed for multi-module help inspection output.

This change is a cross-cutting CLI behavior/prompt adjustment spanning:
- root help routing and text (`cmd/edr/unified_cli.go`),
- standalone risk help text (`cmd/edr/main.go`),
- hostscan/filescan help routing behavior (especially `-r -h` and `--custom ... -h` paths),
- hostscan/filescan argument-selection validation in unified CLI (`--all/--custom/--scan-mode`),
- hostscan/filescan scan execution progress wiring in unified CLI,
- help assertion tests in `cmd/edr/unified_cli_test.go` and progress assertions in `cmd/edr/progress_test.go`.

## Goals / Non-Goals

**Goals:**
- Provide English, sectioned help templates for:
  - `edr -h`
  - `edr hostscan -h`
  - `edr filescan -h`
  - `edr -r -h`
- Keep global long risk option wording aligned with current parser support (`--riskanalyze`).
- Consolidate hostscan/filescan risk guidance into base help pages so `-r -h` no longer requires separate risk-only pages.
- Support `--custom <one-or-many> -h` for hostscan/filescan as module-scoped OPTIONS-only help.
- For multi-module custom help, show only parameter intersection.
- Keep help text and parser behavior aligned for module-selection entry flags (`--all`, `--custom`, `--scan-mode`).
- Restore terminal progress rows for unified `hostscan/filescan` scan execution.

**Non-Goals:**
- Changing scan/risk module execution order or output data structures.
- Introducing new scan/risk flags.
- Refactoring module flag parsers beyond what is needed to render help text consistently.

## Decisions

### 1. Root and risk help move to explicit English section templates
We will rewrite:
- `usage()` in `unified_cli.go` for root help,
- `parseRiskFlags` usage function in `main.go` for standalone risk help.

Rationale:
- Keeps the change local to existing help emitters.
- Avoids touching command execution paths.

Alternatives considered:
- Building a shared templating engine for all help pages. Rejected for now to keep the change bounded and low risk.

### 2. `hostscan/filescan -r -h` will route to consolidated base help output
We will keep parsing `-r` normally but render the same consolidated help shape for `hostscan/filescan` whether help is requested with `-h` or `-r -h`.

Rationale:
- Matches the requested UX that users should not need separate `-r -h` pages.
- Preserves compatibility for users who still type `-r -h`.

Alternatives considered:
- Making `-r -h` an error/deprecated path. Rejected to avoid breaking discoverability.

### 3. `--custom ... -h` help becomes module-scoped OPTIONS output
For both hostscan and filescan:
- single module: show selected module OPTIONS section only,
- multiple modules: compute and display only common/intersection OPTIONS.

Implementation approach:
- Reuse existing filter-intersection logic (`parseHostCommonFilters`, `parseFilescanWebCommonFilters`) as the source-of-truth for which options are shared.
- Add focused help render helpers that output only OPTIONS blocks (English) for single and multi-module custom help scenarios.

Rationale:
- Keeps help-output logic aligned with runtime argument constraints.
- Prevents drift between "help says allowed" and "parser rejects at runtime".

Alternatives considered:
- Parsing module flag `-h` output and text-merging intersections heuristically. Rejected due to fragility and localization artifacts.

### 4. Tests will assert behavior and routing, not brittle full-string equality
Update/add tests to verify:
- section headers and key options exist,
- legacy split risk-help behavior is removed/replaced,
- custom single/multi-module help only includes expected OPTIONS scope.

Rationale:
- Reduces flaky tests while still locking key UX contracts.

### 5. Explicit module-selection entry is required in unified CLI
For non-help execution in unified CLI:
- `edr hostscan` must provide one of `--all` or `--custom`,
- `edr filescan` must provide one of `--all`, `--custom`, or `--scan-mode`.

Rationale:
- Prevents implicit defaults that hide execution intent.
- Keeps runtime behavior aligned with updated help prompts and mutual-exclusion guidance.

Alternatives considered:
- Keeping implicit "all modules" default mode. Rejected because it conflicts with explicit-mode UX and makes operator intent ambiguous.

### 6. Unified hostscan/filescan restore terminal progress display
`runHostscanCLI` and `runFilescanCLI` initialize terminal progress and pass scoped progress callbacks down to module/local scan params.

Rationale:
- Progress feedback existed in legacy command paths and is expected by operators.
- Restoring it in unified CLI improves long-running scan observability without changing scan result schema.

Alternatives considered:
- Printing only coarse per-module start/end logs. Rejected because underlying modules already provide richer `done/total/stage` signals.

## Risks / Trade-offs

- [Risk] Existing tests currently rely on old Chinese snippets and old routing assumptions.
  Mitigation: update assertions to new English tokens and add focused tests for consolidated help behavior.

- [Risk] Multi-module custom help intersection rendering could diverge from runtime parser constraints.
  Mitigation: derive intersection from existing common-filter parser contracts, not from hardcoded duplicated lists.

- [Risk] Users accustomed to previous example-first root help may need adjustment.
  Mitigation: preserve concise command discovery in `COMMANDS` and clear risk entry guidance (`edr -r -h`).

- [Risk] Help and argument-gate refactor can accidentally alter non-help branches in unified routing.
  Mitigation: keep parser changes localized, add explicit negative-path tests, and run targeted + full `go test` regression.

- [Risk] Progress output can interfere with plain stderr assertions in tests or scripts.
  Mitigation: keep progress rendering single-line/carriage-return based, and add focused unit tests for scoped progress formatting.
