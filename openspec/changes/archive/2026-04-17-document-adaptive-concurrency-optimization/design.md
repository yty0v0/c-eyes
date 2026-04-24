## Context

Unified `hostscan` and `filescan` now execute multiple modules concurrently, and local `filescan --scan-mode` uses a worker pool that adapts over time. These runtime behaviors were implemented to reduce latency under real workloads while keeping output contracts stable, but were not captured in the current OpenSpec capability specs.

## Goals / Non-Goals

**Goals:**
- Define observable adaptive-concurrency behavior for hostscan, filescan web mode, and local file-scan pipeline mode.
- Define stable bounds and control signals (CPU/memory/backlog) used for runtime up/down scaling.
- Define compatibility behavior for legacy local concurrency flag removal (`--workers` rejection).
- Preserve accuracy-first behavior by documenting no-intentional-loss requirement for static input snapshots.

**Non-Goals:**
- Introduce a new user-facing concurrency CLI parameter.
- Mandate a single hardcoded worker number for all environments.
- Redefine output schemas, scoring logic, or risk-analysis provider semantics.

## Decisions

### Decision 1: Keep adaptive module scheduling as the default for unified multi-module scans
`hostscan` and web-mode `filescan` use module-level adaptive worker limits with min/initial/max bounds. Runtime metrics (CPU utilization and memory pressure) plus queue backlog drive incremental worker adjustments.

Alternatives considered:
- Fixed worker count only: simple, but underutilizes larger hosts and overloads smaller hosts.
- Unbounded goroutines: high peak throughput risk, but unacceptable pressure spikes and unstable latency.

### Decision 2: Use mode-aware defaults for local file-scan pipeline
Local file-scan pipeline worker profiles depend on scan mode and target volume:
- `path/full`: more aggressive defaults for high task counts.
- `smart`: more conservative defaults due to heterogeneous task characteristics.

Alternatives considered:
- One profile for all modes: easier maintenance, but poor fit across mode-specific workloads.

### Decision 3: Keep environment-based operational overrides without adding CLI flags
Runtime profile bounds remain overrideable via environment variables for controlled operations/testing, while user CLI no longer exposes `--workers` in local filescan mode.

Alternatives considered:
- Reintroduce `--workers`: gives direct control, but conflicts with the desired "automatic by default" runtime contract.

### Decision 4: Treat correctness as a first-class guardrail for optimization
Concurrency tuning is constrained by "result-contract unchanged" expectations:
- For static inputs, optimization must not intentionally drop records.
- Differences in inherently dynamic data sources (for example process snapshots) are treated as runtime variability, not contract drift.

## Risks / Trade-offs

- [Risk] Higher concurrency can increase memory peaks.  
  -> Mitigation: bounded max workers, memory-threshold backoff, and env-level caps.

- [Risk] Runtime metric jitter can cause oscillation near thresholds.  
  -> Mitigation: bounded step changes, periodic tuning cadence, and backlog-aware scaling rules.

- [Risk] Users may expect deterministic row equality on dynamic modules.  
  -> Mitigation: document static-input equivalence scope and dynamic-source variability expectations.

## Migration Plan

1. Add spec deltas for `hostscan`, `filescan`, and `file-scan`.
2. Validate OpenSpec artifacts and ensure apply prerequisites are complete.
3. Keep implementation unchanged; this change documents existing shipped behavior.
4. If rollback is required, revert docs only; runtime behavior is already independently controlled by code and tests.

## Open Questions

- Should we add a formal benchmark appendix in OpenSpec for target throughput ranges by workload class?
