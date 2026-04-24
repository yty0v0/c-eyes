## 1. Upload Gate Policy Update

- [x] 1.1 Remove score-only terminal upload blocker (`mode terminal verdict reached`) from analyzer upload gate.
- [x] 1.2 Keep explicit terminal blockers only (whitelist allow/deny, local high-confidence, cloud high-confidence).
- [x] 1.3 Keep `local_only` behavior unchanged (`-cloud-upload` does not trigger upload).

## 2. Regression Coverage

- [x] 2.1 Add test: unresolved cloud result (`cloud_queried=false`) with `-cloud-upload` enabled MUST attempt upload.
- [x] 2.2 Run riskanalysis upload-related tests and full riskanalysis package tests.

## 3. Build Outputs

- [x] 3.1 Rebuild Windows binary in `dist/edr.exe` with updated upload gate logic.
- [x] 3.2 Rebuild Linux binary in `dist-linux-amd64/edr` with updated upload gate logic.
