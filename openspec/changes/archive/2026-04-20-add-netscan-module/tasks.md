## 1. CLI Entry, Help, and Guardrails

- [x] 1.1 Add `netscan` top-level routing in `cmd/edr/unified_cli.go` aligned with existing module dispatch flow.
- [x] 1.2 Add `c-eyes -h` root help update so `COMMANDS` includes `netscan`.
- [x] 1.3 Add `c-eyes netscan -h` help output with `EXECUTE OPTIONS` and `FILTER OPTIONS` sections in English.
- [x] 1.4 Enforce collection-only boundary by rejecting `-r/--riskanalyze` and risk-only flags for `netscan`.

## 2. Request Model and Argument Validation

- [x] 2.1 Define `internal/netscan` request structs for execute options and filter options from `docs/netscan.md`.
- [x] 2.2 Implement target parsing for `target` and `targetFile` (CIDR, single IP, IPv4 range, mixed list) with deduplication.
- [x] 2.3 Implement `exclude` application and `maxTargets` hard-limit rejection.
- [x] 2.4 Implement validation/defaults for `scanMode`, `ipv6`, `tcpPorts`, `udpPorts`, `pps`, `workers`, `timeoutMs`, and `jitterMs`.

## 3. Probe Orchestration and Mode Execution

- [x] 3.1 Implement unified probe planner/executor for modes `A, ICP, ICA, ICT, T, TS, U, N, O`.
- [x] 3.2 Implement capability matrix logic by OS/protocol so unsupported mode-target combinations are skipped with English warnings.
- [x] 3.3 Implement privilege pre-checks and English permission errors for modes requiring elevated privileges.
- [x] 3.4 Implement mode-gated port probing for `T/TS/U` using `tcpPorts` and `udpPorts`.

## 4. Adaptive Runtime Control

- [x] 4.1 Implement always-on adaptive controller sampling CPU/memory and adjusting effective rate/concurrency.
- [x] 4.2 Treat user-provided `pps` and `workers` as hard upper bounds while allowing adaptive downscale/upscale.
- [x] 4.3 Integrate jitter and timeout behavior into per-target probe scheduling.
- [x] 4.4 Add runtime metrics/warnings to support troubleshooting of throttling and skipped probes.

## 5. Persistence and Classification

- [x] 5.1 Add local SQLite store for netscan assets (Windows/Linux home path resolution, schema init, migration-safe open).
- [x] 5.2 Implement deterministic `assetId` generation (`sha1(ip|mac)` else `sha1(ip)`) with normalization rules.
- [x] 5.3 Implement `firstSeen` and `lastSeen` update semantics across repeated runs.
- [x] 5.4 Implement `managedSource` loader integration (json/csv/xlsx) with matching precedence `ip+mac` then `ip`.

## 6. Output Shaping, Filtering, and Verification

- [x] 6.1 Implement normalized output envelope (`total`, `rows`) and row schema fields including optional port findings.
- [x] 6.2 Implement post-collection filters (`assetStatus`, `keyword`) and deterministic sorting (`sortBy`, `sortOrder`).
- [x] 6.3 Wire netscan results into existing global output pipeline (`-o` json/csv/xlsx) and dedupe flow.
- [x] 6.4 Add CLI and package tests for parsing, guardrails, capability skips, permission errors, persistence continuity, and managed-source matching.
- [x] 6.5 Run `openspec validate --strict --changes add-netscan-module` and fix any validation issues.

## 7. Post-Conversation Hardening and Semantics Alignment

- [x] 7.1 Change default no-target strategy to primary-interface C-segment discovery (instead of all private interfaces).
- [x] 7.2 Ensure mode-scoped output fields: only emit port findings for mode-relevant runs; keep inapplicable fields null/empty.
- [x] 7.3 Align `TS` fallback provenance so `sources` reflects effective path (`tcp_connect`) in current build.
- [x] 7.4 Fix adaptive worker-slot completion behavior to avoid post-100% hangs under throttled concurrency.
- [x] 7.5 Render netscan progress row before informational lines to keep pinned progress at top.
- [x] 7.6 Harden `targetFile` parsing for UTF-8 BOM-prefixed comment lines and add regression test.
- [x] 7.7 Clarify `A`-mode non-ARP-compatible fallback behavior and warning semantics in OpenSpec.
- [x] 7.8 Update netscan help spec to require mode legend with full-name expansion and default mode declaration.
