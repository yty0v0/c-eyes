## 1. Unified CLI Command Wiring

- [x] 1.1 Add `benchmark` command routing in `cmd/edr/unified_cli.go` root dispatcher and usage command list.
- [x] 1.2 Implement benchmark argument parser with `--template auto|windows|linux|euleros|kylin` and default `auto`.
- [x] 1.3 Add benchmark help output (`c-eyes benchmark -h`) in English with collection-only and privilege notes.
- [x] 1.4 Add benchmark collection-only guardrails to reject `-r/--riskanalyze` and risk-only options with explicit English errors.

## 2. Runtime and Execution Model

- [x] 2.1 Package benchmark assets for Windows/Linux/EulerOS/Kylin inside the repository.
- [x] 2.2 Implement template resolver for Windows, Linux, EulerOS, and Kylin with `auto` default.
- [x] 2.3 Implement privilege preflight checks (Windows administrator, Linux-family root).
- [x] 2.4 Implement runtime dependency checks for required command engines.
- [x] 2.5 Replace Windows packaged-script execution with Go-native collectors plus YAML rule evaluation.
- [x] 2.6 Remove bundled Windows original script assets from the benchmark package path.

## 3. Result Model and Evaluation

- [x] 3.1 Normalize benchmark rows and summary metrics in `internal/benchmark`.
- [x] 3.2 Add Windows YAML rule metadata fields (`check_name`, `expected`, `severity`, `recommendation`) and evaluation logic.
- [x] 3.3 Add explicit evaluation metadata (`status`, `evaluated`, `status_reason`, `execution_status`).
- [x] 3.4 Validate Linux-family execution and encoding behavior with native/template-compatible tests.

## 4. Evidence and Retention

- [x] 4.1 Remove exported `raw_xml_path` row field.
- [x] 4.2 Remove exported top-level `raw_xml_paths`.
- [x] 4.3 Stop retaining raw XML evidence copies after scan completion.
- [x] 4.4 Keep runtime XML as internal transient processing only where still needed.

## 5. Presentation and Export UX

- [x] 5.1 Improve benchmark progress display to use weighted total progress instead of a flat stage percentage.
- [x] 5.2 Simplify benchmark progress text to remove child-step detail from the terminal progress line.
- [x] 5.3 Add benchmark export display model for CSV/XLSX with concise Chinese report columns.
- [x] 5.4 Map user-visible benchmark statuses to human-readable labels (`符合/不符合/信息项/待确认/检查失败`).
- [x] 5.5 Show `整改建议` only for actionable rows.
- [x] 5.6 Normalize exported Windows display identifiers to `WIN-*` / `WIN-DISP-*`.
- [x] 5.7 Keep terminal benchmark summary in English while switching exported summary CSV/XLSX sheet labels to Chinese.

## 6. Validation

- [x] 6.1 Add/adjust CLI tests for benchmark routing, parser behavior, help text, and risk-flag rejection.
- [x] 6.2 Add parser and evaluation tests for benchmark summary and display mapping behavior.
- [x] 6.3 Add benchmark export tests for CSV/XLSX summary sheets and report-oriented main table headers.
- [x] 6.4 Rebuild all four distribution directories after major benchmark presentation/runtime changes.

## 7. Next-Step Follow-ups

- [x] 7.1 Continue humanizing `actual` values for the most common benchmark rows.
- [ ] 7.2 Consider adding category/risk aggregation sections to exported benchmark summaries.
- [x] 7.3 Decide whether Linux / EulerOS / Kylin should remain template-driven long term or follow Windows de-scripted architecture later.
