## Context

`netscan` currently defaults to primary-interface IPv4 C-segment discovery when `-target/-targetFile` are not provided. This keeps scans safe and predictable, but it cannot surface routed private segments that are reachable from the current host.  
The change must remain collection-only, cross-platform (Windows/Linux), and must not use shell command execution for route/connection discovery. Existing guardrails (`maxTargets`, adaptive worker/pps ceilings, risk-flag rejection, global `-o` output) must remain intact.

## Goals / Non-Goals

**Goals:**
- Add an explicit opt-in switch for reachable-segment discovery in `netscan`.
- Discover routed private subnet candidates from local host visibility (route table + active connections) using in-process logic.
- Verify candidate segments with lightweight gateway-oriented probes before treating them as reachable.
- Keep behavior deterministic and bounded, with explicit warnings/metrics for operator transparency.
- Preserve existing default behavior when the new option is not enabled.

**Non-Goals:**
- Full enterprise network enumeration across every routed host by default.
- Any risk-analysis behavior (`-r`, cloud upload, yara chaining, etc.).
- Bypassing firewall/network policy controls.
- Replacing current explicit-target workflows (`target`, `targetFile`) with automatic expansion.

## Decisions

### 1) CLI contract: explicit opt-in flag
- Add `-reachableSegments` (bool, default `false`) under `netscan` execute options.
- When `false`, keep current behavior unchanged (including “primary-interface C-segment” default messaging).
- When `true`, run an additional reachable-segment workflow in the same scan execution.

Rationale:
- Preserves backward compatibility and avoids surprise fan-out.
- Keeps safety posture explicit and operator-controlled.

Alternatives considered:
- Always-on reachable-segment discovery: rejected due to scan-surface expansion and behavior drift.
- Separate command/module: rejected to avoid duplicated orchestration and output pipelines.

### 2) Candidate discovery uses passive local facts first
- Introduce a reachability collector layer in `internal/netscan`:
  - `collectRouteCandidates()` from OS route APIs/files (Windows/Linux specific implementations).
  - `collectConnectionCandidates()` from local active connection tables (best-effort).
- Normalize to private CIDRs only (`10/8`, `172.16/12`, `192.168/16`), dedupe, and attach evidence sources.
- Exclude loopback/link-local/multicast/default-route catch-all entries from candidate set.

Rationale:
- Passive sources are low-noise, cheap, and compliant with “no shell command collection.”
- Route + connection evidence together improves confidence compared with either alone.

Alternatives considered:
- Blindly probing RFC1918 supernets: rejected due to high noise and poor boundedness.
- Dependency on external tools (`route`, `ip`, `netstat`): rejected by requirement.

### 3) Reachability verification is gateway-oriented and bounded
- For each candidate CIDR, build a small deterministic verification list:
  - explicit route next-hop (if private and valid),
  - common gateway endpoints (`.1`, `.2`, `.254`) for IPv4 segments.
- Verification order:
  - ICMP Echo (when privilege/capability allows),
  - TCP connect fallback on a short fixed set (`445`, `3389`, `22`, `80`).
- Mark segment reachable on first positive response; otherwise keep as unverified.
- Keep per-segment probe budget fixed and small.

Rationale:
- Confirms routed reachability without expensive full-subnet host probing.
- Compatible with existing probe primitives and adaptive controls.

Alternatives considered:
- Full target expansion per routed CIDR: rejected for MVP due to scale/risk.
- TTL traceroute-style path inference in first release: deferred due to additional complexity and privilege variance.

### 4) Integration with existing scan pipeline
- Add a pre-probe stage in `Scan()`:
  - `discover_reachable_segments` (new progress stage label).
- Produce reachable-segment summary as metrics; optionally include verified gateway IPs as additional probe targets if within bounded budget.
- Preserve `maxTargets` as hard safety boundary; auto-added targets must not bypass it.
- Continue using existing adaptive tuner for active probe stages.

Rationale:
- Minimal refactor; reuse existing normalization/output framework.
- Maintains current safety semantics and predictable failure model.

Alternatives considered:
- Separate execution pipeline and output envelope: rejected to avoid duplicated contract and emit logic.

### 5) Output and observability changes are additive
- Extend `RuntimeMetrics` with reachable-segment fields, for example:
  - `reachableCandidateSegments`
  - `reachableVerifiedSegments`
  - `reachableSegments` (list of CIDR + evidence + verification method)
- Keep row schema backward-compatible; avoid breaking required row fields.
- Warnings must clearly indicate skipped/limited cases (permission, unsupported family, budget cap).

Rationale:
- Gives operators actionable evidence without breaking downstream consumers.

Alternatives considered:
- New top-level output document for reachability only: rejected; increases integration and compatibility cost.

## Risks / Trade-offs

- [OS route/connection API differences] -> Use per-OS collectors behind a shared interface; degrade gracefully with warnings when unavailable.
- [False positives from permissive gateway/proxy behavior] -> Require explicit per-segment verification evidence and surface method/source in metrics.
- [Potential scan-time increase with many candidate segments] -> Enforce fixed candidate/verification budgets and reuse adaptive throttling.
- [Privilege variance for ICMP on some systems] -> Automatically fallback to TCP verification and emit explicit permission warnings.
- [Output consumers expecting exact metrics shape] -> Add fields only (no removals/renames), keep existing keys stable.

## Migration Plan

1. Add new CLI flag parse/help wiring and parameter plumbing (`reachableSegments`).
2. Implement reachability candidate collectors and normalized candidate model.
3. Implement bounded verification stage and integrate into `Scan()` orchestration.
4. Extend runtime metrics and ensure output serialization remains backward-compatible.
5. Add/adjust tests:
   - CLI parse/help behavior
   - default behavior unchanged when flag is absent
   - candidate filtering and verification logic
   - maxTargets safety with auto-added targets
6. Run `openspec validate --strict --change add-netscan-reachable-segments` and full test pass for touched packages.

Rollback strategy:
- Disable `-reachableSegments` execution path via code flag guard and retain baseline `netscan` behavior.
- Revert added metrics fields only if integration issues occur downstream.

## Open Questions

- Should verified routed segments in MVP add only gateway targets, or also add a small deterministic host seed list per segment?
- Should Linux connection-derived candidates include UDP flows, or TCP-established only for noise control?
- Do we need a user-facing cap parameter for candidate segments now, or rely on internal fixed bounds in first release?
