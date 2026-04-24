## 1. Capture Performance-Behavior Deltas

- [x] 1.1 Summarize adaptive module-concurrency behavior for unified `hostscan` execution.
- [x] 1.2 Summarize adaptive module-concurrency behavior for unified web-mode `filescan` execution.
- [x] 1.3 Summarize mode-aware local `filescan --scan-mode` pipeline concurrency behavior and automatic tuning signals.
- [x] 1.4 Record local `filescan --workers` removal as a behavior-level contract change.

## 2. Add OpenSpec Delta Files

- [x] 2.1 Add `hostscan` spec delta with adaptive module concurrency requirement and scenarios.
- [x] 2.2 Add `filescan` spec delta for adaptive web-module concurrency and `--workers` rejection behavior.
- [x] 2.3 Add `file-scan` spec delta for mode-aware adaptive local pipeline profile behavior.
- [x] 2.4 Add result-contract preservation requirement for static input snapshots under adaptive profiles.

## 3. Validate and Publish Change Artifacts

- [x] 3.1 Run `openspec validate --strict --no-interactive` and fix any artifact or formatting issues.
- [x] 3.2 Confirm change status reports proposal/design/specs/tasks present and ready for downstream apply/archive workflow.
