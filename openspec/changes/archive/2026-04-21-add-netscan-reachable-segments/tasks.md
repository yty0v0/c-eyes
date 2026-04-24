## 1. CLI Contract and Surface

- [x] 1.1 Add `-reachableSegments` parsing in `parseNetscanArgs` and map it into `netscan.Params`.
- [x] 1.2 Update `netscanUsage()` execute options text to document `-reachableSegments` and bounded behavior notes.
- [x] 1.3 Add/adjust CLI tests in `cmd/edr/unified_cli_test.go` for help output and argument parsing coverage.

## 2. Data Model and Result Contract

- [x] 2.1 Extend `internal/netscan/types.go` with `Params.ReachableSegments` and additive reachable-segment metric fields.
- [x] 2.2 Ensure normalization/default logic preserves backward compatibility when `reachableSegments` is unset.
- [x] 2.3 Add unit tests for new parameter defaults and metric serialization behavior.

## 3. Candidate Segment Discovery

- [x] 3.1 Introduce a reachability candidate model and shared filtering/normalization utilities in `internal/netscan`.
- [x] 3.2 Implement Windows route/connection candidate collectors using in-process APIs (no shell command invocation).
- [x] 3.3 Implement Linux route/connection candidate collectors using in-process sources (no shell command invocation).
- [x] 3.4 Add tests for candidate deduplication, RFC1918 scoping, and exclusion of loopback/link-local/default-route entries.

## 4. Reachability Verification and Boundedness

- [x] 4.1 Implement deterministic gateway-oriented verification target planning for each candidate segment.
- [x] 4.2 Implement lightweight verification probing with ICMP-first and TCP fallback behavior.
- [x] 4.3 Wire bound checks and warning emission for skipped candidates/probes due to safety or capability limits.
- [x] 4.4 Add tests for verification success/failure classification and bounded probe behavior.

## 5. Scan Pipeline Integration

- [x] 5.1 Integrate reachable-segment discovery stage into `Scan()` behind `reachableSegments=true`.
- [x] 5.2 Preserve existing default no-target behavior when `reachableSegments` is disabled.
- [x] 5.3 Populate runtime metrics with candidate/verified segment counts and evidence summaries.
- [x] 5.4 Ensure any auto-derived probe targets still respect `maxTargets` and adaptive runtime ceilings.

## 6. End-to-End Validation

- [x] 6.1 Add or update integration-style tests covering enabled/disabled mode behavior and warning visibility.
- [x] 6.2 Run `go test ./internal/netscan ./cmd/edr`.
- [x] 6.3 Run `openspec validate --strict --change add-netscan-reachable-segments` and fix validation findings.
