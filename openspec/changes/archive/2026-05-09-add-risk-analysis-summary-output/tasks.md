## 1. Summary Data Model

- [x] 1.1 Add a reusable risk-summary aggregation structure derived from final `RiskAssessment.RiskLevel` values
- [x] 1.2 Implement category counting for `高危`, `高风险`, `中风险`, `低风险`, `分析中`, and `可疑-需本地核实`, while excluding `无风险` from rendered metrics
- [x] 1.3 Add unit tests for summary aggregation across mixed risk-level outputs

## 2. JSON and Terminal Output

- [x] 2.1 Update standalone and chained risk JSON output paths to emit `{ summary, results }` instead of a bare result array
- [x] 2.2 Expand terminal completion summary to print the new category set for non-zero counts
- [x] 2.3 Add/adjust tests for standalone `-r` and chained `hostscan/filescan -r` JSON/terminal summary behavior

## 3. Excel Output

- [x] 3.1 Extend risk Excel export to append a dedicated `summary` sheet while preserving the existing main results sheet
- [x] 3.2 Add tests verifying the summary sheet contains the expected risk categories and counts

## 4. Verification

- [x] 4.1 Run targeted risk-analysis output tests for standalone and chained modes
- [x] 4.2 Run `openspec validate --strict --no-interactive` and fix any artifact/spec issues
