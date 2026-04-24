## Why

When `-cloud-upload` is enabled, the current upload gate still skips some unresolved files due to a low/high pre-score terminal check. In practice, this can suppress cloud evidence collection exactly when hash lookup is ineffective (`cloud_queried=false`) and operators explicitly requested upload fallback.

## What Changes

- Update upload gating in risk analysis so `cloud_upload` acts as a true fallback evidence path for unresolved records.
- Keep `local_only` behavior unchanged (never upload in local-only mode).
- Remove score-based "mode terminal verdict" upload skip behavior for non-`local_only` modes.
- Preserve explicit terminal conclusions as upload blockers:
  - whitelist terminal decisions (`allow` / `deny`)
  - local high-confidence conclusion
  - cloud high-confidence conclusion
- Add regression coverage for unresolved cloud results to ensure upload is attempted.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `risk-analysis`: Refine cloud upload gating semantics so unresolved records in `cloud_only`/`fast`/`smart`/`deep` attempt upload when `-cloud-upload` is enabled, instead of being skipped by score-only terminal heuristics.

## Impact

- Affected code:
  - `internal/riskanalysis/analyzer.go`
  - `internal/riskanalysis/analyzer_upload_test.go`
- Runtime behavior:
  - More records can enter upload stage when cloud hash lookup is ineffective.
  - Auto-budget finalized `U` may increase compared to old behavior.
- No API shape changes; output fields remain compatible.
