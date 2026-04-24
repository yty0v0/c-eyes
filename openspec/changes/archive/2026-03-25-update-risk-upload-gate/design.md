## Context

The existing upload gate in `internal/riskanalysis/analyzer.go` treated very low/high pre-score as a terminal verdict and skipped upload (`mode terminal verdict reached`). This behavior conflicts with operator intent when `-cloud-upload` is explicitly enabled to collect fallback cloud evidence for unresolved records (for example, `cloud_queried=false`).

Current constraints:
- `local_only` must remain non-uploading.
- Existing output contract (`cloud_upload_*` fields) must stay backward compatible.
- Upload blockers should represent explicit conclusions, not heuristic score-only shortcuts.

## Goals / Non-Goals

**Goals:**
- Make `-cloud-upload` effective for unresolved records in online modes (`cloud_only`, `fast`, `smart`, `deep`).
- Keep explicit terminal conclusions as upload blockers (whitelist terminal, local high-confidence, cloud high-confidence).
- Preserve `local_only` no-upload behavior.
- Add regression coverage to prevent reintroduction of score-only blocking.

**Non-Goals:**
- No change to cloud provider APIs or upload task schema.
- No change to risk score computation formulas.
- No change to CLI flags or JSON field names.

## Decisions

1. Remove score-only terminal gating from upload decision path.
- Decision: Delete the `preScore <= 5 || preScore >= 95` block in `shouldBlockUpload`.
- Rationale: score-only terminal is heuristic and can hide evidence collection when cloud lookup is ineffective.
- Alternative considered: keep score threshold but lower/raise bounds.
  - Rejected because any threshold-based shortcut can still skip unresolved-but-uploadable records.

2. Keep explicit high-confidence/whitelist terminal blockers.
- Decision: `shouldBlockUpload` only blocks on:
  - whitelist `allow`/`deny`
  - high-confidence local
  - high-confidence cloud
- Rationale: these represent explicit conclusions with strong evidence and avoid unnecessary upload.

3. Simplify upload-block function signature.
- Decision: remove unused parameters (`mode`, `meta`, `stage`) from `shouldBlockUpload`.
- Rationale: reduces ambiguity and keeps policy focused on evidence state, not incidental stage metadata.

4. Add unresolved-cloud regression test.
- Decision: add a test case where `cloud_queried=false` but upload is enabled and target uploadable; expected behavior is upload attempt.
- Rationale: directly captures the operator-facing failure mode.

## Risks / Trade-offs

- [Risk] Increased upload attempts can raise cloud API cost and latency.
  - Mitigation: keep existing explicit blockers and uploadability checks; budget already scales with actual upload count `U`.

- [Risk] Existing automation relying on historical "mode terminal verdict reached" skip reason may observe changed behavior.
  - Mitigation: reason strings remain structured, and skip behavior still occurs for explicit terminal conclusions.

- [Risk] More uploads under poor cloud-hash availability may increase pending/failed task volume.
  - Mitigation: retain provider policy/rate-limit controls and surfaced `cloud_upload_tasks` diagnostics.
