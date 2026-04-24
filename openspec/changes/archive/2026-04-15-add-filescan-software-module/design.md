## Context

`filescan` currently supports web-mode modules `site`, `framework`, and `jarpackage`, plus local file scan modes. There is no software-application module under `filescan`, which leaves a contract gap for software inventory collection that should follow the same cross-platform and non-command collection constraints as existing web modules.  
This change is cross-cutting because it affects CLI module selection/help, collection/filter logic, unified aggregation/export behavior, and chained risk mapping.

## Goals / Non-Goals

**Goals:**
- Add `software` as a first-class `filescan` web-mode module (single-module and `--all` paths).
- Implement software collection for Windows and Linux without launching external command-line tools.
- Follow a service-first, static-plus-dynamic strategy and include install evidence rows when `binPath/configPath` can be normalized.
- Support requested filters: `groups`, `hostname`, `ip`, `name`, `version`, `binPath`, `configPath`.
- Define stable software output schema with list-based IP fields and associated process list.
- Keep `filescan -r` behavior aligned by mapping software records to risk inputs via `binPath` and `configPath`.
- Keep CLI help and custom module option prompts in English and aligned with current unified CLI style.

**Non-Goals:**
- Adding standalone command `edr software-scan` (this capability is delivered through `edr filescan` module selection).
- Introducing software risk scoring fields into scan output.
- Reworking existing risk engine semantics or adding new risk modes.
- Building a remote/orchestrated inventory service.

## Decisions

### 1. Add `internal/softwarescan` package with cross-platform collectors and normalized row model
We will create a dedicated package mirroring existing scan-module patterns:
- `types.go`: params/results/types.
- `scan.go`: orchestration (collect -> host enrich -> normalize -> filter).
- `scan_windows.go` / `scan_linux.go`: platform collectors.
- `filter.go`: module-specific filtering semantics.

Rationale:
- Keeps module boundaries consistent with existing `web*scan` packages.
- Limits coupling and makes platform behavior testable.

Alternatives considered:
- Embedding software collection directly into unified CLI. Rejected due to poor testability and architectural drift.

### 2. Use a B+ collection strategy (service-focused + install evidence with normalized paths)
Collection sources will prioritize runtime-correlated service software, then append install-evidence rows only when paths are actionable:
- Runtime/dynamic evidence: process metadata (`name`, `path`, `startArgs`, user, PID) and in-process correlation.
- Static evidence: OS-native files/registries/configs readable in-process (no `os/exec`).

Platform direction:
- Windows: service metadata and uninstall/installation registry evidence plus process correlation.
- Linux: service/config/package metadata files plus process correlation.

Rationale:
- Produces higher-signal inventory than raw package dumps.
- Preserves actionable `binPath/configPath` for chained risk analysis.

Alternatives considered:
- Full package inventory only. Rejected due to high noise and weaker runtime relevance.
- Runtime-only inventory. Rejected because it misses installed-but-not-running software that still has actionable paths.

### 3. Keep output contract list-based for host IPs and software-centric for rows
Software row contract will include:
- Host metadata: `externalIpList`, `internalIpList`, `bizGroupId`, `bizGroup`, `remark`, `hostTagList`, `hostname`.
- Software metadata: `name`, `version`, `uname`, `binPath`, `configPath`.
- Process correlation: `processes[]` objects with `pid`, `name`, `uname`.

`displayIp` is intentionally omitted for this capability, and scalar `externalIp/internalIp` fields are not used.

Rationale:
- Matches the user-approved direction for array-based IP representation.
- Keeps rows software-centric while preserving process detail without row explosion.

Alternatives considered:
- Process-flattened row model (one row per process). Rejected for higher duplication and weaker inventory readability.

### 4. Integrate `software` into unified filescan behavior and help contracts
Changes in unified CLI will include:
- Extend `filescanWebModuleOrder` with `software`.
- Add single-module flag parser/help for software filters.
- Add `software` option catalog entries for `edr filescan --custom <mode> -h`.
- Preserve multi-module intersection rules (`groups/hostname/ip`) for web-mode combinations.

Rationale:
- Keeps behavior consistent with existing module-scoped and intersection-scoped help/validation.

Alternatives considered:
- Granting extra intersection params across multi-module mode. Rejected to avoid breaking current filescan parameter contract.

### 5. Map software rows to risk inputs via path candidates
For `filescan -r`, software rows will be converted using:
- `target_type = file`
- candidate keys: `binPath`, `configPath`

Records without path candidates can still pass through as raw scan records; path-bearing rows will expand to candidate-specific risk records using existing candidate mapping behavior.

Rationale:
- Aligns with current hostscan/filescan chained-risk path mapping approach.

Alternatives considered:
- Disabling risk chaining for software module. Rejected because user requirement is to align with existing web module behavior under `-r`.

## Risks / Trade-offs

- [Risk] Software source heterogeneity across distributions/Windows variants may produce uneven coverage.  
  Mitigation: use multiple in-process evidence sources and normalize with deterministic dedupe keys.

- [Risk] Permissions can prevent reading some config/package metadata paths.  
  Mitigation: best-effort collection with null/empty fallback per field; never fail whole scan for per-row field gaps.

- [Risk] Over-collection can increase noise in `--all` mode.  
  Mitigation: service-first precedence and dedupe by normalized software identity + path signatures.

- [Risk] Path candidate expansion may increase chained risk workload.  
  Mitigation: candidate dedupe and reuse existing `collectCandidatePaths` behavior.

## Migration Plan

1. Add new `software-scan` and `filescan` delta specs for contract-level behavior.
2. Implement `internal/softwarescan` package and targeted Windows/Linux/filter tests.
3. Wire unified CLI module dispatch/help/option catalog and add risk candidate mapping.
4. Update output/export wiring (JSON/Excel through existing unified output path).
5. Run targeted and full regression (`go test ./...`) and verify `edr filescan --custom software` and `edr filescan --all -r`.

Rollback strategy:
- Remove `software` from filescan module order/dispatch and keep other modules unchanged.
- The change is additive at CLI/module level and has no data migration requirement.

## Open Questions

- Should unsupported package ecosystems (for example niche distro package stores) be ignored silently or reported via diagnostics in verbose mode?
- Should future iterations add a configurable allowlist/blocklist for software name normalization to reduce environment-specific noise?
