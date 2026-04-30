## Context

`c-eyes benchmark` is now implemented, but the implementation diverged from the original design in several intentional ways:

- Windows no longer runs the original vendor `.vbs` bundle.
- Windows now uses Go-native collection plus YAML rule metadata.
- Exported benchmark data is no longer a raw technical payload by default; it is shaped into a concise report view for CSV/XLSX.
- Raw XML retention was removed after review because it leaked too much execution detail and was not needed in the final operator-facing result.

This design document updates the benchmark architecture to match the implemented behavior and captures the next-step direction established in the conversation.

## Goals / Non-Goals

**Goals**
- Preserve a unified `benchmark` command with strict privilege gates and template routing.
- Keep Windows baseline logic distributable without shipping original Windows script files.
- Keep Linux / EulerOS / Kylin benchmark behavior compatible with packaged runtime checks.
- Produce benchmark exports that make compliance state obvious immediately.
- Separate internal execution details from user-facing report fields.

**Non-Goals**
- Expose every internal benchmark field to end users.
- Preserve retained raw XML evidence files in exported result payloads.
- Treat exported CSV/XLSX as a debugging view.

## Current Architecture

### 1. CLI and routing

`cmd/edr/unified_cli.go` routes `c-eyes benchmark` through:

- argument parsing
- privilege/runtime dependency checks
- benchmark execution
- summary printing
- unified output emission

The command remains collection-only and rejects risk-analysis options.

### 2. Template execution model

#### Windows

Windows now uses a native implementation:

- Go collectors for host, account, service, network, share, hotfix, firewall, filesystem, startup, and security-policy sources
- YAML-defined rule metadata and evaluator configuration
- trace XML may still be assembled transiently inside the runtime path when needed for compatibility, but it is not retained or surfaced in exports

This design intentionally avoids packaging original Windows `.vbs` / `scripten.exe` assets.

#### Linux / EulerOS / Kylin

Linux-family templates now use a Unix native benchmark path that:

- executes script-aligned collection commands and local collectors
- applies YAML-defined rule metadata and evaluation
- shapes results into the same report-oriented export model as Windows

The implementation goal is not byte-for-byte script replay; it is semantic alignment with each original template while using a native collector/rule architecture.

### 3. Result model split

There are now two conceptual result layers:

#### Internal result layer

Used for collection/evaluation logic:

- template
- metadata
- summary metrics
- per-row evaluation details

This layer may contain fields that are useful for debugging or machine reasoning.

#### Export/report layer

Used for CSV/XLSX benchmark presentation:

- `检查项编号`
- `检查项名称`
- `分类`
- `基线要求`
- `实际结果`
- `判定结果`
- `风险等级`
- `整改建议`
- `证据摘要`

This layer deliberately hides or collapses technical fields such as:

- execution status internals
- status reason internals
- command/source details
- raw XML references

### 4. Identifier normalization

To make report output visually consistent:

- Windows rule identifiers are normalized to `WIN-*`
- Windows informational rows are normalized to `WIN-DISP-*`

The original internal identifiers are preserved in code paths where compatibility matters, but exported display identifiers use the normalized style.

### 5. Summary language split

The benchmark summary now follows a language split:

- terminal summary: English
- exported summary CSV / XLSX sheet: Chinese

This keeps CLI interaction consistent with the unified command style while making report files friendlier to their target audience.

## Decisions

### Decision 1: Benchmark is officially native collector + YAML-driven

- Decision: Accept Windows and Linux-family native collector + YAML rule evaluation as the intended architecture.
- Rationale: avoids script leakage, reduces packaging sensitivity, and allows readable rule metadata and report shaping.
- Trade-off: behavior is aligned to original template semantics rather than exact script execution flow.

### Decision 2: Raw XML is an internal transient artifact only

- Decision: do not export `raw_xml_path` or `raw_xml_paths`, and do not retain raw XML copies after scan completion.
- Rationale: reduces leakage of execution details and simplifies user-facing payloads.
- Trade-off: post-run forensic replay from retained XML is no longer available by default.

### Decision 3: Exported benchmark files are report views, not raw internal rows

- Decision: shape benchmark CSV/XLSX output into a concise display model.
- Rationale: operators need “是否符合标准” to be obvious immediately.
- Trade-off: exported files no longer expose every internal field directly.

### Decision 4: Status display should be human-centered

- Decision: map internal states to display labels:
  - `pass` -> `符合`
  - `fail` -> `不符合`
  - informational unknown -> `信息项`
  - undecided unknown -> `待确认`
  - execution failures -> `检查失败`
- Rationale: avoids exposing implementation-centric wording such as `unknown` to report consumers.

### Decision 5: Recommendation display should be selective

- Decision: show `整改建议` only for rows that require action or confirmation.
- Rationale: always-on recommendations create noisy reports and weaken the visual signal of true failures.

## Risks / Trade-offs

- [Risk] EulerOS / Kylin final CLI validation still depends on target runtime availability.
  -> Mitigation: accept WSL package-level maximum-coverage validation as the current verification ceiling and keep real target-distro validation as follow-up.

- [Risk] Hiding internal fields in exported files may reduce debugging convenience.
  -> Mitigation: retain richer JSON structure internally where needed and keep code-level diagnostics available.

- [Risk] Two identifier forms (internal vs display) can confuse maintainers.
  -> Mitigation: clearly document display-ID normalization and keep the transformation in one output-layer function.

## Next-Step Plan

1. Continue refining benchmark exported presentation:
   - add category/risk aggregation views where useful
2. Continue Linux-family rule strengthening:
   - upgrade weak presence-based rules where higher-confidence structured signals are available
3. Continue documenting which fields are:
   - internal-only
   - exported-only
   - shared
