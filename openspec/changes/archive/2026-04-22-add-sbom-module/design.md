## Context

The unified CLI currently supports `hostscan`, `filescan`, `eventlog`, and `netscan`, but no SBOM command exists. Users need software bill-of-materials collection in the same CLI and output pipeline, without introducing a parallel toolchain.

The local SBOM codebase at `C:\Users\Administrator\Desktop\sbom` already implements core SBOM collection/conversion logic (source/package/artifact phases and SPDX/XSPDX formatting), but it is not integrated into `edrsystem` module layout, command routing, or global output rules.

Constraints:
- Keep SBOM collection-only (no risk-analysis chaining).
- Reuse global `-o/--output` instead of module-level output flags.
- Require explicit `-p/--path` scan scope for `sbom`.
- Keep prompts/errors/help in English.
- Support Windows and Linux behavior in the unified command.

## Goals / Non-Goals

**Goals:**
- Add a first-class `c-eyes sbom` command aligned with unified CLI architecture.
- Integrate the SBOM implementation as an internal package and provide a stable command adapter.
- Require explicit `-p/--path` for SBOM scan scope.
- Support SBOM format selection: `xspdx-json` (default) and `spdx-json`.
- Enforce SBOM output as JSON only, while still using global `-o`.
- Provide SBOM-specific default output when `-o` is omitted: `result.json`, `result1.json`, ... in CWD.
- Make help/error behavior consistent with existing module UX and collection-only modules (`eventlog`/`netscan`).

**Non-Goals:**
- Implement SBOM risk scoring or vulnerability analysis.
- Introduce CSV/XLSX SBOM exports in this change.
- Redesign all global output behavior for non-SBOM commands.
- Rewrite SBOM collectors for new ecosystems beyond current imported capability.

## Decisions

### Decision 1: Integrate SBOM as internal module with CLI adapter
- Decision: Vendor/adapt the local SBOM code into `internal/sbom` (or equivalent package namespace) and expose a narrow entrypoint used by `cmd/edr/unified_cli.go`.
- Rationale: Keeps existing architecture (command adapters over internal modules), minimizes behavior drift, and enables incremental maintenance.
- Alternatives considered:
  - Execute an external SBOM binary: rejected due to deployment complexity and weaker testability.
  - Implement SBOM from scratch in current repo: rejected due to high effort and redundant logic.

### Decision 2: Add dedicated `sbom` subcommand in unified router
- Decision: Extend root command dispatch and help catalogs to include `sbom` as a peer of existing modules.
- Rationale: Matches user requirement for module parity and keeps invocation discoverable.
- Alternatives considered:
  - Nest SBOM under `filescan`: rejected because user explicitly requires a standalone module.

### Decision 3: Separate output path from SBOM content format
- Decision: Keep `-o/--output` for file path only, and add `--format` for SBOM content (`xspdx-json|spdx-json`).
- Rationale: Preserves global output contract and avoids overloading path semantics.
- Alternatives considered:
  - Infer content format from filename: rejected (ambiguous and non-standard).
  - Add module-level output flag: rejected by existing unified output policy.

### Decision 3.1: Require explicit scan root via -p/--path
- Decision: `c-eyes sbom` requires `-p/--path` and rejects missing path with an English argument error.
- Rationale: Prevent accidental broad/narrow scans caused by implicit working-directory scope and improve reproducibility.
- Alternatives considered:
  - Implicit current working directory default: rejected due to ambiguity and operator error risk.

### Decision 4: SBOM command enforces JSON output and custom default auto-name
- Decision:
  - If `sbom` uses explicit `-o`, suffix must be `.json`.
  - If `sbom` omits `-o`, use `result*.json` auto-increment in CWD.
- Rationale: SBOM payload is schema-centric JSON; this keeps behavior predictable while preserving global flag usage.
- Alternatives considered:
  - Keep global default `result*.xlsx` for sbom: rejected as incompatible with SBOM schema output.

### Decision 5: SBOM is collection-only
- Decision: Reject `-r/--riskanalyze` and risk options when command is `sbom`, with explicit English error text.
- Rationale: Aligns with requirement and existing collection-only command behavior patterns.
- Alternatives considered:
  - Ignore risk flags silently: rejected due to poor UX and hidden misconfiguration.

### Decision 6: Normalize `docs/sbom.md` to UTF-8 and update wording
- Decision: Re-encode and clean requirement text to remove mojibake and reflect final flag semantics (`-o` only for output path, no `-p` output flag).
- Rationale: Documentation must be a reliable baseline for future changes.

## Risks / Trade-offs

- [Risk] Importing third-party/local SBOM code increases dependency and maintenance surface.
  → Mitigation: Wrap integration behind internal adapter interfaces and keep tests around command-level behavior.

- [Risk] SBOM-specific output defaults may diverge from generic global-output assumptions.
  → Mitigation: Constrain divergence to `sbom` command branch only and document it in `global-output` delta spec.

- [Risk] Format conversion mismatches (`xspdx-json` vs `spdx-json`) could cause interoperability confusion.
  → Mitigation: Set explicit default (`xspdx-json`), validate accepted values, and document usage in help text.

- [Risk] Cross-platform file/path behavior differences can break deterministic output naming.
  → Mitigation: Reuse existing path utilities and add tests for auto-increment behavior and suffix validation.

## Migration Plan

1. Introduce capability specs and tasks for SBOM command, output behavior, and help updates.
2. Integrate SBOM package code under internal module namespace and fix imports.
3. Add `sbom` route, parser, help output, and collection-only risk guardrails in unified CLI.
4. Implement SBOM output handling (`--format`, `.json` enforcement, `result*.json` default) and explicit `-p/--path` requirement.
5. Add/adjust tests for parse rules, help text, and output-path behavior.
6. Update `docs/sbom.md` in UTF-8 and align wording with implemented behavior.
7. Run `openspec validate --strict` and related Go tests.

Rollback strategy:
- Revert `sbom` route registration and internal module wiring while keeping existing commands unchanged.
- Because this is additive, rollback is low-risk and isolated to new files and sbom-specific branches.

## Open Questions

- None blocking for implementation. The command-level behavior, output defaults, and format policy are confirmed.
