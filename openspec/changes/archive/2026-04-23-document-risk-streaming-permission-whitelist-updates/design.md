## Context

This change documents behavior that already shipped across `filescan`, chained/standalone `risk analyze`, `internal/filescan` collection, and project whitelist bootstrap paths.  
The missing OpenSpec records create drift risk: operators now depend on streaming risk output, concise permission failures, and default-on project baseline whitelisting, but those contracts were not explicitly captured in spec deltas.

The change is cross-cutting:
- CLI output/rendering (`cmd/edr/unified_cli.go`, `cmd/edr/main.go`, `cmd/edr/progress.go`)
- file target collection and permission handling (`internal/filescan`)
- risk engine callback and runtime emission behavior (`internal/riskanalysis`)
- whitelist setup policy (`cmd/edr/project_whitelist.go`)

## Goals / Non-Goals

**Goals:**
- Record risk streaming and summary output as a normative CLI contract.
- Record risk progress stability constraints for terminals with long wrapped log lines.
- Record filescan permission reporting behavior (root-deny error + per-entry warning semantics).
- Record default-on project baseline whitelist behavior and environment override semantics.

**Non-Goals:**
- Redesign risk scoring math, cloud provider policy, or YARA rule logic.
- Introduce new scan modes or output file formats.
- Replace existing progress rendering infrastructure globally for all modules.

## Decisions

1. Document streaming risk output as a requirement under `risk-analysis` instead of module-specific docs only.
- Rationale: both standalone and chained risk paths share the analyzer contract.
- Alternative considered: document only in `filescan`. Rejected because standalone risk mode uses the same behavior.

2. Split permission behavior across `filescan` and `file-scan`.
- Rationale: `filescan` owns user-facing CLI behavior, while `file-scan` owns collector-level semantics.
- Alternative considered: record only one capability. Rejected due to ambiguity between runtime collection and CLI reporting.

3. Treat project baseline whitelist as a `risk-whitelist-policy` concern.
- Rationale: the behavior affects whitelist funnel inputs (enterprise baseline hash repository) and trust decisions.
- Alternative considered: record only in implementation notes. Rejected because default-on behavior is operator-visible and policy-impacting.

4. Specify terminal-stable risk progress behavior as output contract, not implementation detail.
- Rationale: operators need one interpretable progress row during streaming output regardless of terminal wrapping quirks.
- Alternative considered: avoid spec coverage and keep best-effort behavior. Rejected because this caused repeated field regressions.

## Risks / Trade-offs

- [Risk] Terminal capabilities differ across Windows/Linux shells and remote TTYs.  
  → Mitigation: require stable single-row progress behavior and color fallback to plain text when ANSI is unsupported.

- [Risk] Permission-denied reporting can be noisy in large protected trees.  
  → Mitigation: constrain reporting to inaccessible entries encountered by walker boundaries (no recursive synthetic child errors).

- [Risk] Default-on project whitelist could mask misconfiguration if root detection silently fails.  
  → Mitigation: keep explicit-enable failure signaling and explicit environment override controls.
