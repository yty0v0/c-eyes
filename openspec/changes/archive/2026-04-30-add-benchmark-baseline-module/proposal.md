## Why

The original benchmark integration goal was to turn standalone baseline artifacts into a first-class `c-eyes benchmark` command. During implementation, two more constraints became clear:

- Benchmark assets must not leak original script artifacts in source or packaged output.
- Raw script-oriented output is difficult for operators to read directly; the result needs a report-oriented presentation that makes compliance obvious at a glance.

The benchmark module therefore evolved from “run packaged scripts and parse XML” into a mixed model:

- keep Linux-family support compatible with packaged template behavior
- replace Windows script execution with Go-native collectors plus YAML rule evaluation
- standardize result presentation for terminal/JSON/CSV/XLSX output

This OpenSpec change must now reflect the implementation that actually exists and the next-step plan that the conversation established.

## What Changes

- Add a first-class `benchmark` command aligned with the unified CLI module model.
- Support template selection with `--template auto|windows|linux|euleros|kylin` and `auto` default.
- Enforce elevated privilege:
  - Windows requires administrator
  - Linux-family requires root
- Keep `benchmark` collection-only:
  - reject `-r/--riskanalyze`
  - reject risk-only options
- Implement Windows baseline collection as:
  - Go-native collectors
  - YAML-configured rule metadata and rule evaluation
  - no bundled original script artifacts
- Implement Linux / EulerOS / Kylin benchmark through Unix native collection and YAML rule metadata while preserving template semantics without retaining original script artifacts.
- Remove persisted raw XML references from exported benchmark results:
  - no `raw_xml_path`
  - no top-level `raw_xml_paths`
  - no retained raw XML copies in temp evidence directories
- Improve benchmark presentation:
  - progress bar uses smooth weighted total progress
  - terminal summary remains English
  - exported result tables become Chinese, compact, and report-oriented
  - exported summary sidecars/sheets use Chinese labels
- Normalize display identifiers for exported benchmark reports:
  - Windows rule rows use `WIN-*`
  - Windows informational rows use `WIN-DISP-*`
  - reserve equivalent prefixes for Linux-family templates

## Capabilities

### New Capabilities
- `benchmark-scan`: Run packaged baseline collection with template routing, privilege checks, normalized summary metrics, and report-oriented exports.

### Modified Capabilities
- `cli-help-prompts`: Benchmark command help remains English and structured while benchmark file exports use operator-friendly Chinese presentation.

## Impact

- Affected code:
  - `cmd/edr` benchmark routing, output shaping, CSV/XLSX summary generation, and progress display
  - `internal/benchmark` template routing, privilege checks, Windows native collectors, YAML rule evaluation, parser/summary logic
  - benchmark asset packaging and Windows de-scripted asset layout
- Affected behavior:
  - benchmark packaging no longer depends on original script assets for any template
  - benchmark exported files now prioritize human-readable report structure over raw internal fields
  - benchmark outputs no longer expose raw XML file retention paths
- Follow-on plan:
  - continue polishing Linux / EulerOS / Kylin rule strength and result wording
  - use WSL package-level maximum-coverage validation for `euleros` / `kylin` until real target-distro CLI validation is available
  - continue deciding which internal fields remain machine-only versus user-visible
