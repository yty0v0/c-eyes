## Context

The current risk-analysis implementation has partial summary behavior in terminal streaming, but it is limited to coarse severity-band output and is not reflected in JSON or Excel exports. Benchmark output already has a richer pattern: a top-level JSON summary, a dedicated Excel `summary` sheet, and concise terminal summary rows. The new risk summary should align with that operator-facing model while preserving risk-specific states such as `分析中` and `可疑-需本地核实`.

Current constraints:
- Risk analysis is available through standalone `-r` and scan-chained `hostscan/filescan -r`
- Existing risk JSON output is a bare array of `AnalysisResult`
- Existing Excel risk output uses only a `risk_analysis` results sheet
- Existing risk levels include `无风险`, `低风险`, `中风险`, `高风险`, `高危`, `分析中`, and `可疑-需本地核实`

The user confirmed that `无风险` should not be summarized, while special degraded/failsafe states should be included as explicit summary categories rather than collapsed into standard risk bands.

## Goals / Non-Goals

**Goals:**
- Add a stable risk summary data model reusable across terminal, JSON, and Excel outputs
- Cover all currently supported risk-analysis invocation paths
- Report counts for `高危`, `高风险`, `中风险`, `低风险`, `分析中`, and `可疑-需本地核实`
- Exclude `无风险` from rendered summary metrics
- Reuse the benchmark-style destination patterns where they improve operator readability

**Non-Goals:**
- Change risk scoring formulas or risk-level derivation rules
- Add chained risk support to collection-only modules that do not currently support `-r`
- Introduce CSV summary sidecars unless later required
- Redesign unrelated global output behaviors outside risk-summary handling

## Decisions

### Decision 1: Use explicit risk-summary object instead of implicit consumer-side aggregation
- Decision: Risk outputs SHALL compute a first-class summary object before serialization/export.
- Rationale: Centralizing aggregation avoids drift between terminal, JSON, and Excel destinations and prevents each consumer from reimplementing category counting.
- Alternatives considered:
  - Leave JSON/Excel as raw results only: rejected because it preserves the existing operator pain.

### Decision 2: Wrap risk JSON output as `{ summary, results }`
- Decision: JSON output SHALL move from a bare array to an object with top-level `summary` and `results`.
- Rationale: This matches the benchmark output shape and creates a durable place for summary without inventing sidecar files for JSON.
- Alternatives considered:
  - Add summary as a fake row in the array: rejected because it breaks result typing and downstream parsing.
  - Emit separate `*.summary.json`: rejected because the user prefers integrated summary when reasonable.

### Decision 3: Keep special unresolved states separate from standard severity bands
- Decision: `分析中` and `可疑-需本地核实` SHALL be counted as their own summary categories, while `无风险` SHALL be omitted from rendered summary metrics.
- Rationale: These states communicate materially different operator actions from `高/中/低` severities and should not be flattened.
- Alternatives considered:
  - Map both states into medium risk: rejected because it destroys degraded-cloud-state meaning.

### Decision 4: Align Excel and terminal behavior with benchmark-style presentation
- Decision:
  - Excel risk exports SHALL gain a dedicated `summary` sheet
  - terminal risk completion SHALL print a fuller summary block
- Rationale: The benchmark module already established a readable pattern for summaries, and reusing it reduces UX inconsistency.
- Alternatives considered:
  - Keep terminal summary as the only summary output: rejected because file exports would still lack operator-level overview.

### Decision 5: Scope summary coverage to currently supported risk entry paths only
- Decision: The summary requirement SHALL apply to standalone `-r`, chained `hostscan -r`, and chained `filescan -r`.
- Rationale: This matches the actual supported risk surface and avoids overpromising unsupported collection-only modules.
- Alternatives considered:
  - Phrase requirement as “all scan modules”: rejected because benchmark/sbom/eventlog/netscan do not currently support chained risk.

## Risks / Trade-offs

- [Risk] Changing risk JSON from array to object is a breaking contract for existing consumers.
  -> Mitigation: Document the breaking change explicitly in proposal/specs and keep field naming simple (`summary`, `results`).

- [Risk] Risk-level summaries may drift from result-level classification if aggregation logic is duplicated.
  -> Mitigation: Implement a single summary aggregator over final `RiskAssessment.RiskLevel` values and reuse it for every destination.

- [Risk] Terminal summary output may become noisy if all categories are printed unconditionally.
  -> Mitigation: Print total always, and print category rows only when counts are non-zero, except where explicit product wording requires otherwise.

- [Risk] Excel summary formatting may diverge from benchmark summary sheet conventions.
  -> Mitigation: Reuse existing summary-sheet writer patterns where possible and keep metrics list deterministic.

## Migration Plan

1. Define OpenSpec deltas for risk-analysis and global-output summary behavior.
2. Introduce a shared risk summary aggregation structure from final analysis results.
3. Update JSON serialization for risk outputs to emit `{ summary, results }`.
4. Extend Excel writer to append a `summary` sheet for risk exports.
5. Extend terminal completion summary to include the expanded category set.
6. Update tests for standalone and chained risk outputs.
7. Run OpenSpec validation and targeted Go tests.

Rollback strategy:
- Revert JSON wrapper and summary-sheet/terminal-summary changes while keeping result-level risk analysis intact.
- Because scoring behavior is unchanged, rollback is mostly limited to output-layer code.

## Open Questions

- Whether CSV risk exports should later gain a summary sidecar remains open, but it is not required for this change.
