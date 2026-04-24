## Why

The current EDR CLI can collect host, file, and eventlog data, but it cannot discover unmanaged internal-network assets. A dedicated `netscan` module is needed now to provide controlled host discovery and asset mapping without enabling risk analysis.

## What Changes

- Add a new top-level `c-eyes netscan` module aligned with `hostscan`, `filescan`, and `eventlog` command architecture.
- Define execute options and filter options for network discovery, including multi-target input (`target`, `targetFile`), multi-mode probing (`A, ICP, ICA, ICT, T, TS, U, N, O`), IPv6 toggle, exclusion controls, and adaptive runtime caps.
- Define default target behavior when no explicit target is provided: scan only the primary interface C-segment by default.
- Define normalized `netscan` output schema with asset identity, host/network attributes, status classification (`managed/unmanaged/ignored`), scan provenance, and optional port findings for `T/TS/U/O`.
- Enforce mode-scoped output fields so mode-inapplicable findings remain null/empty (for example, `A`-only runs do not emit port findings).
- Ensure fallback semantics are explicitly represented in provenance (for example, `TS` fallback reports effective source as `tcp_connect`).
- Clarify `A` mode fallback behavior when native ARP path is not applicable, with explicit English warnings and mode-scoped output guarantees.
- Make `targetFile` parsing robust for UTF-8 BOM + comment lines.
- Enforce collection-only boundaries: `netscan` rejects `-r/--riskanalyze` and risk-only flags.
- Add local persistence for stable `assetId` tracking and `firstSeen/lastSeen` continuity across runs.
- Add `managedSource`-based reconciliation for managed/unmanaged classification using deterministic matching rules.
- Extend CLI help prompts to include `netscan` and separate `EXECUTE OPTIONS` and `FILTER OPTIONS` sections for this module.
- Improve runtime UX so the progress row is rendered first and remains pinned above informational lines.

## Capabilities

### New Capabilities
- `netscan-scan`: Cross-platform internal host discovery and asset mapping with adaptive throttling, managed-source reconciliation, and normalized output.

### Modified Capabilities
- `cli-help-prompts`: Add `netscan` to root command help and define module help layout with `EXECUTE OPTIONS` and `FILTER OPTIONS` sections.

## Impact

- Affected code:
  - `cmd/edr/unified_cli.go` (top-level route, args parsing, help text, risk-flag rejection wiring)
  - New `internal/netscan/*` package for target parsing, probe orchestration, persistence, classification, and result shaping
  - `cmd/edr/unified_cli_test.go` and new `internal/netscan/*_test.go` coverage
- Affected specs:
  - New: `openspec/changes/add-netscan-module/specs/netscan-scan/spec.md`
  - Modified delta: `openspec/changes/add-netscan-module/specs/cli-help-prompts/spec.md`
- Dependencies/systems:
  - Reuse existing global output pipeline (`-o` json/csv/xlsx)
  - Reuse runtime adaptive control patterns and local multi-format record loading semantics
  - Introduce local SQLite persistence for netscan asset cache
