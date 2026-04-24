## Context

`c-eyes` currently exposes two top-level scanning entries: `hostscan` and `filescan`, with a separate risk-analysis path enabled by `-r/--riskanalyze`. There is no dedicated top-level module for normalized host event-log collection, even though host logs are a primary data source for incident investigation and operational auditing.

The new module must collect host logs (Windows/Linux), not EDR-internal logs, and MUST run without invoking external shell commands for collection. It must also remain strictly collection-only: no risk scoring, no risk verdicts, and no risk-chain parameters.

## Goals / Non-Goals

**Goals:**
- Add a unified top-level command `c-eyes eventlog` for host event-log collection.
- Define a stable, paged, filterable output contract aligned with existing scan aggregate style (`total/pageNo/pageSize/hasMore/rows`).
- Normalize cross-platform fields (`source`, `eventType`, `eventLevel`, `eventCode`, `eventAction`, `result`) and preserve traceability with stable `logId`.
- Reuse global output behavior via `-o/--output` for `.json/.csv/.xlsx`.
- Enforce collection-only behavior by rejecting `-r/--riskanalyze` and risk-only flags for this module.

**Non-Goals:**
- Performing risk analysis, risk scoring, alerting, or remediation output.
- Building a full SIEM ingestion pipeline or distributed log aggregation service.
- Backfilling historical logs beyond configured query window constraints.

## Decisions

1. Command model: add `eventlog` as a top-level module without a public `scan` subcommand.
   - Rationale: `hostscan/filescan` unified routing in current CLI is top-level module driven. Keeping `eventlog` at this level simplifies discovery and keeps help/usage consistent.
   - Alternative considered: `c-eyes eventlog scan`; rejected to avoid introducing a third command pattern.

2. Collection-only enforcement: `eventlog` rejects risk mode and risk-only parameters.
   - Rationale: requirement boundary explicitly excludes risk analysis, and mixed behavior would create ambiguous output expectations.
   - Alternative considered: allow `-r` and ignore silently; rejected because silent ignore causes operational confusion.

3. Cross-platform normalization with an internal collector abstraction.
   - Rationale: Windows/Linux log sources differ by API and metadata shape; abstraction allows source-specific collection with a common normalized output record.
   - Alternative considered: one shared parser with platform conditionals only; rejected for maintainability and testability.

4. Filter semantics: field-level AND, array value OR, keyword as additional AND constraint.
   - Rationale: deterministic query behavior and easier client expectations.
   - Alternative considered: keyword OR with structured filters; rejected because it broadens results unexpectedly.

5. Stable pagination and ordering.
   - Decision: support `sortBy` whitelist and use deterministic tie-break ordering (at minimum by `timestamp` + `logId`) to avoid duplicate/missed rows across pages.
   - Rationale: host logs can share identical timestamps under bursty workloads.

6. `rawContent` safety policy.
   - Decision: default not returned; when requested, return structured object with sensitive-key redaction and truncation marker.
   - Rationale: balances forensic detail with payload size and secret leakage risk.

7. `logId` stability policy.
   - Decision: prefer native stable identifiers from log backends; fallback to deterministic hash from normalized key fields.
   - Rationale: enables de-duplication and incremental workflows across repeated queries.

## Risks / Trade-offs

- [Risk] Cross-platform mapping drift causes inconsistent `eventType`/`eventLevel` values.
  - Mitigation: centralize mapping tables and add fixture-based tests for Windows/Linux samples.

- [Risk] High-volume time windows degrade query latency and memory.
  - Mitigation: enforce bounded `pageSize`, validate time window limits, stream/early-filter by time/source at collector stage.

- [Risk] Permission constraints prevent reading some log sources.
  - Mitigation: return partial results with per-record/source fallback behavior and explicit errors for unrecoverable source access failures.

- [Risk] `rawContent` contains sensitive material.
  - Mitigation: default off, redact known secret keys, truncate oversized payloads, and annotate truncation.

## Migration Plan

1. Add `eventlog` command route and argument parsing in unified CLI.
2. Implement platform collectors and normalization/filter/sort/paging pipeline.
3. Integrate output emission through existing global `-o/--output` path.
4. Update root help command list to include `eventlog`.
5. Validate contract with unit/integration tests using representative source fixtures.

Rollback strategy:
- If regressions appear, remove `eventlog` route from command switch and keep existing modules unchanged; no data migration is required.

## Open Questions

- Linux source priority policy when both journald and file-backed logs are available on the host.
- Final default time-window cap value for large hosts (e.g., 7 days vs 31 days) based on performance tests.
