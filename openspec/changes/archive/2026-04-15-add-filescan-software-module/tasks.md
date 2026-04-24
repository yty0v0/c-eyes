## 1. Software Scan Module Skeleton

- [x] 1.1 Create `internal/softwarescan` package structure (`types.go`, `scan.go`, `filter.go`, `scan_windows.go`, `scan_linux.go`, `scan_stub.go`).
- [x] 1.2 Define software params/result contracts in `types.go` with filters (`groups`, `hostname`, `ip`, `name`, `version`, `binPath`, `configPath`) and output fields (`externalIpList`, `internalIpList`, host metadata, software metadata, `processes`).
- [x] 1.3 Implement normalization helpers so software rows always emit stable keys with null/empty fallbacks and omit scalar `externalIp/internalIp` fields.

## 2. Cross-Platform Collection And Filtering

- [x] 2.1 Implement Linux collector using in-process file/runtime evidence (no `os/exec`) and produce software-centric rows with optional install-evidence enrichment.
- [x] 2.2 Implement Windows collector using in-process OS/registry/runtime evidence (no `os/exec`) and produce normalized software rows.
- [x] 2.3 Implement process correlation to aggregate related runtime processes into `processes[]` on a single software row.
- [x] 2.4 Implement filter logic aligned with existing filescan web-module semantics (host intersection behavior plus software field filtering).
- [x] 2.5 Add deterministic dedupe logic for software identity/path evidence to control noise in `--all` output.

## 3. Filescan CLI Integration

- [x] 3.1 Extend unified filescan module order/selection to include `software` in `--custom` and `--all` paths.
- [x] 3.2 Add software module flag parsing (`parseSoftwareScanFlags`) and wire single-module execution path in `runFilescanWebSingleModule`.
- [x] 3.3 Add software common-filter execution path in `runFilescanWebModuleWithCommonFilters` for multi-module mode.
- [x] 3.4 Update filescan usage/help/custom-option catalog to include `software` and module-scoped `--custom software -h` options in English.
- [x] 3.5 Wire chained risk mapping for software rows with path candidates `binPath` and `configPath`.

## 4. Output, Tests, And Verification

- [x] 4.1 Ensure unified JSON/CSV/Excel output paths include software rows with contract-aligned field names.
- [x] 4.2 Add unit tests for software filters, normalization, dedupe, and process aggregation behavior.
- [x] 4.3 Add CLI tests for `--custom software`, `--all` inclusion, multi-module intersection constraints, and `--custom software -h`.
- [x] 4.4 Add risk-chain tests to verify software rows emit `target_path` candidates from `binPath/configPath` under `filescan -r`.
- [x] 4.5 Run targeted and full regression (`go test ./...`) and validate key commands: `edr filescan --custom software`, `edr filescan --all`, `edr filescan --custom software -r`, and `edr filescan --custom software -h`.
