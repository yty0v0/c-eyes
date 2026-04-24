## Why

Current `c-eyes` workflows focus on host inventory (`hostscan`) and file/web inventory (`filescan`), but they do not provide a unified first-class entry for host event-log collection. We need an `eventlog` module now to support structured, cross-platform host log retrieval with consistent filtering, pagination, and output behavior, while explicitly excluding risk analysis.

## What Changes

- Add a new top-level command module `c-eyes eventlog` for host event-log information collection (not EDR-internal logs).
- Define cross-platform request/response contracts for event-log querying, including time range, structured filters, paging, sorting, and optional raw payload return.
- Standardize event normalization fields (source, type, level, action, code, result, process/user/network/target context) for Windows/Linux log sources.
- Enforce collection-only scope: reject `-r/--riskanalyze` and risk-analysis-only flags under `eventlog` with argument errors.
- Reuse unified global output behavior (`-o/--output`) for JSON/CSV/XLSX export paths.
- Update root help command discovery so users can find `eventlog` alongside existing top-level modules.

## Capabilities

### New Capabilities
- `eventlog-scan`: Provide a unified `c-eyes eventlog` host-log collection capability with structured filtering, normalized output schema, pagination/sorting, and collection-only constraints.

### Modified Capabilities
- `cli-help-prompts`: Extend root help command listing and guidance to include `eventlog` as a top-level module.

## Impact

- Affected code:
  - CLI routing and argument parsing in `cmd/edr` (new `eventlog` command path, help text, risk-flag rejection for this module).
  - New internal package for host log collection/filter/normalization (Windows/Linux collectors and mapping logic).
  - Unified output emission integration for `eventlog` results.
- Affected APIs/contracts:
  - Introduces `eventlog` request/response contract (paged `total/pageNo/pageSize/hasMore/rows` with normalized log fields).
- Dependencies/systems:
  - Uses in-process OS log APIs/readers only (no external command invocation).
  - No risk-analysis pipeline dependency for `eventlog`.
