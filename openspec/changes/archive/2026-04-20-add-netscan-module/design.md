## Context

The CLI currently exposes three top-level collection workflows (`hostscan`, `filescan`, `eventlog`) and a shared output path contract (`-o`) for JSON/CSV/XLSX emission. There is no first-class module for internal network asset discovery, unmanaged asset identification, or cross-run asset timeline continuity.

Constraints:
- Must run on Windows and Linux.
- Must use in-process collection/probing logic (no shelling out to command-line tools for discovery).
- Must remain collection-only; risk-analysis paths and flags are disallowed.
- Must preserve existing CLI conventions: unified top-level routing, consistent error model, and global output handling.

Stakeholders:
- Security operations users who need unmanaged-host visibility.
- Platform maintainers who require bounded network impact (rate limiting, adaptive controls).

## Goals / Non-Goals

**Goals:**
- Introduce `c-eyes netscan` as a top-level module aligned with current CLI architecture.
- Support execution options and filter options documented in `docs/netscan.md`.
- Support nine probe modes (`A, ICP, ICA, ICT, T, TS, U, N, O`) with capability-aware platform/protocol handling.
- Keep adaptive tuning always enabled while honoring manual ceilings (`pps`, `workers`).
- Persist asset identity and timeline locally to provide stable `assetId`, `firstSeen`, and `lastSeen`.
- Reconcile discovery output with `managedSource` using deterministic matching.
- Reuse global output and deduplication behavior.

**Non-Goals:**
- No risk-analysis chaining (`-r`) from `netscan`.
- No centralized server-side orchestration or leader election in this change.
- No GUI workflow; CLI only.
- No full vulnerability assessment logic beyond discovery/classification metadata.

## Decisions

1. **Add a new internal package `internal/netscan` and top-level `netscan` command route.**
   - Rationale: keeps scan concerns isolated, mirrors module boundaries used by `eventlog` and `filescan`.
   - Alternative considered: extending existing `portscan`. Rejected because `portscan` models local listening-port inventory rather than subnet discovery.

2. **Keep `netscan` collection-only and hard-reject risk flags.**
   - Rationale: consistent with eventlog collection-only semantics and reduces unsafe coupling with unrelated risk workflows.
   - Alternative considered: allow chained risk mode. Rejected as scope creep and operator confusion for network discovery module.

3. **Use capability-aware execution for nine probe modes with explicit warnings/errors in English.**
   - Rationale: user requested all modes while allowing platform/protocol practical limits.
   - Behavior:
     - Unsupported mode for target protocol/platform: skip with warning.
     - Permission-required mode without privileges: fail mode execution with explicit English error.
   - Alternative considered: strict hard-fail for any unsupported mode. Rejected because it harms mixed-mode usability.

4. **Enable adaptive tuning by default, with manual ceilings only.**
   - Rationale: protects host and network under variable load while preserving operator control.
   - Mechanics:
     - Runtime sampler reads CPU/memory.
     - Dynamic controller adjusts effective `pps/workers/jitter` within hard bounds.
     - User-specified `pps/workers` are treated as upper bounds.
   - Alternative considered: fixed static values only. Rejected due to higher overload risk in heterogeneous hosts.

5. **Persist asset state in local SQLite cache.**
   - Rationale: required for stable cross-run identity and accurate `firstSeen/lastSeen` semantics.
   - Proposed storage: `%USERPROFILE%/.c-eyes/netscan-assets.db` on Windows and `$HOME/.c-eyes/netscan-assets.db` on Linux.
   - Alternative considered: ephemeral in-memory cache. Rejected because `firstSeen` becomes meaningless after process exit.

6. **Define stable asset identity as deterministic hash of normalized network keys.**
   - Rule:
     - If MAC present: `sha1(normalized_ip + "|" + normalized_mac)`
     - If MAC missing: `sha1(normalized_ip)`
   - Rationale: deterministic and portable across runs.
   - Alternative considered: random UUID on each run. Rejected because it breaks state continuity.

7. **Define `managedSource` reconciliation precedence as `ip+mac` first, then `ip`.**
   - Rationale: reduces false positive managed matches when IPs are reused.
   - Alternative considered: IP-only matching. Rejected as lower precision in DHCP-heavy environments.

8. **Keep output contract aligned with existing global emitters.**
   - Rationale: avoids new output plumbing and keeps behavior consistent with existing modules.
   - Alternative considered: module-specific writer. Rejected due to duplication and divergence risk.

9. **Default target scope SHALL use primary-interface C-segment discovery when no explicit target is provided.**
   - Rationale: improves operator predictability and avoids accidental multi-interface amplification (for example, VM/WSL/VPN adapters).
   - Behavior:
     - Detect preferred source interface via route selection.
     - Generate default IPv4 targets from one C-segment (`x.x.x.1~254`) of the selected primary interface.
   - Alternative considered: scan all private interfaces by default. Rejected due to noisy and often surprising target expansion.

10. **Result fields SHALL be mode-scoped.**
    - Rationale: output should reflect requested/eligible probe modes, not internal fallback artifacts.
    - Behavior:
      - Port fields (`openPorts`, `openTcpPorts`, `openUdpPorts`, `portScanModes`) are emitted only when corresponding port-probe modes are selected.
      - `A`-only runs keep port fields null/empty.
    - Alternative considered: always emit merged findings regardless of selected mode. Rejected because it obscures operator intent and mode semantics.

11. **Probe provenance (`sources`) SHALL represent effective execution path.**
    - Rationale: fallback behavior must be auditable.
    - Behavior:
      - When `TS` falls back to TCP connect in current build, `sources` reports `tcp_connect`.
    - Alternative considered: report configured mode source only. Rejected because it can misrepresent actual probe mechanics.

12. **`targetFile` parsing SHALL tolerate UTF-8 BOM and comments.**
    - Rationale: many editors emit BOM by default; BOM-prefixed comment lines should not break scans.
    - Behavior:
      - Strip BOM prefix before blank/comment checks.
    - Alternative considered: strict raw-line parsing. Rejected due to avoidable operator friction.

13. **Adaptive worker-slot waiting SHALL be completion-aware to avoid post-100% hangs.**
    - Rationale: concurrency throttling can leave workers waiting forever unless completion is observable.
    - Behavior:
      - Worker slot wait path exits when global completed-target count reaches total.
    - Alternative considered: context-cancel-only exit. Rejected because normal successful scans should not require cancellation to terminate.

14. **Progress row SHALL be rendered before informational lines for netscan CLI UX.**
    - Rationale: keeps progress pinned at top and avoids visual jitter/confusion.
    - Behavior:
      - Initialize one progress frame before printing no-target informational notices.
    - Alternative considered: print notices first. Rejected due to inverted visual hierarchy.

15. **`A` mode fallback behavior SHALL be explicit for non-ARP-compatible contexts.**
    - Rationale: operators must understand what happens when targets are not suitable for native ARP (for example IPv6 or off-path environments).
    - Behavior:
      - For non-IPv4 targets, `A` mode is skipped with explicit English warning.
      - Where native ARP execution is unavailable in current build, compatibility probing may run with explicit English warning.
      - Compatibility fallback must not violate mode-scoped output guarantees (`A`-only runs keep port fields null/empty).
    - Alternative considered: silent implicit fallback. Rejected due to operator confusion and audit ambiguity.

## Risks / Trade-offs

- **[Risk] High-noise modes may trigger defensive controls in sensitive networks** → Mitigation: bounded defaults, adaptive tuning always on, explicit exclusion support, and operator-facing warning guidance.
- **[Risk] Mode support differences across OS/protocol combinations can confuse users** → Mitigation: capability matrix in docs + explicit English skip/error messages.
- **[Risk] Local cache growth over time** → Mitigation: periodic compaction and stale-record TTL cleanup policy.
- **[Risk] IP reuse can misclassify asset continuity when MAC is missing** → Mitigation: dual-key identity strategy and confidence reduction when MAC unavailable.
- **[Risk] SYN/advanced probes need elevated privileges on some systems** → Mitigation: clear permission checks and actionable English error messages.

## Migration Plan

1. Add `netscan` route and help sections to unified CLI.
2. Introduce `internal/netscan` package (target parsing, probing, adaptive runtime controller, persistence, reconciliation, output shaping).
3. Wire `netscan` output through existing global `emitOutput` pipeline.
4. Add compatibility tests for:
   - risk-flag rejection
   - execute/filter option parsing
   - adaptive bound behavior
   - persistence (`firstSeen/lastSeen` continuity)
   - managedSource matching precedence
5. Rollout with conservative default probing values and mode-level warnings.
6. Rollback strategy: disable command routing to `netscan` while retaining package code for later fixes.

## Open Questions

- None blocking. Operational defaults for adaptive thresholds will be validated and tuned during implementation tests, with documented fallback values.
