## Context

Two SBOM changes have already landed:
- native image collection target support (`--image`, `--image-archive`, `--oci-layout`)
- containerd backend support for `--image`

Those changes solved the user-facing feature gap, but the backend implementation is still mostly custom code assembled inside `internal/sbom/image_target.go`. The reference tool already has a deeper and more mature image backend architecture covering daemon/archive/OCI/remote image loading, backend-specific metadata, and export behavior. The current project is now at the point where continuing to hand-refine the custom layer is less efficient than selectively aligning the backend implementation to the reference tool.

This change is not about copying an entire external tool wholesale. It is about replacing or heavily adapting the image backend layer while preserving:
- current `c-eyes sbom` CLI
- current SBOM generation flow
- collection-only scope
- current JSON output contract

## Goals / Non-Goals

**Goals:**
- align backend architecture and behavior with the reference tool as closely as practical
- reduce bespoke image backend code in `internal/sbom`
- preserve the current command surface and collection-only boundaries
- improve parity for backend coverage, diagnostics, and future maintainability
- keep imported/adapted code isolated in a dedicated backend-focused package structure

**Non-Goals:**
- import the reference tool's full vulnerability scanning stack
- replace the project's existing SBOM document generation layer
- redesign the `c-eyes sbom` CLI or global output contracts
- guarantee byte-for-byte identical behavior across every runtime/backend in one pass

## Decisions

### Decision 1: Reuse the reference backend layer selectively, not the entire tool
- Decision: The project SHALL import, vendor, or port only the image backend layer needed for image-source handling, while keeping the current CLI and SBOM generation pipeline.
- Rationale: This captures the highest-value maturity from the reference tool without importing unrelated scanner, database, and output systems.
- Alternatives considered:
  - Continue evolving hand-rolled backend code: rejected because parity will remain expensive and drift-prone.
  - Vendor the full tool unchanged: rejected because it would conflict with the current project architecture and collection-only boundary.

### Decision 2: Keep a narrow adapter boundary between backend layer and SBOM generation
- Decision: Image backend code SHALL terminate at a normalized image/rootfs handoff boundary used by the project's existing SBOM generation flow.
- Rationale: This preserves the value of the existing SBOM pipeline and limits blast radius when backend code changes.
- Alternatives considered:
  - Let imported backend code dictate report/output flow: rejected because it would collapse project boundaries.

### Decision 3: Isolate backend-aligned code in dedicated internal packages
- Decision: Reference-aligned backend logic SHALL live in clearly isolated internal packages/modules rather than being spread across existing command and scan orchestration files.
- Rationale: This keeps attribution, maintenance, testing, and future upgrades tractable.

### Decision 4: Preserve public CLI and output contracts while allowing backend-internal behavior to shift
- Decision: The user-facing `sbom` flags and collection-only JSON output contract SHALL remain stable, even if the backend source-resolution internals change substantially.
- Rationale: The backend is the unstable surface we want to improve; the CLI and output contract should remain the stable surface.

## Risks / Trade-offs

- [Risk] Partial backend transplantation may still leave subtle behavior gaps with the reference tool.
  -> Mitigation: treat parity as backend-by-backend and artifact-by-artifact, with explicit comparison-driven tests.

- [Risk] Imported backend code increases dependency and attribution obligations.
  -> Mitigation: isolate packages clearly, keep a traceable provenance record, and avoid importing unrelated subsystems.

- [Risk] Replacing backend internals could regress already working archive/OCI/image flows.
  -> Mitigation: preserve the current adapter contract and run focused regression suites across all image-source modes.

- [Risk] Backend alignment may expose differences between the reference tool's assumptions and this project's SBOM generation assumptions.
  -> Mitigation: keep a normalization layer between imported backend objects and local SBOM generation input.

## Migration Plan

1. Identify the minimal reference-tool backend packages/flows to port or align.
2. Introduce an isolated backend package boundary under `internal/sbom`.
3. Replace current ad hoc backend code path-by-path with reference-aligned logic.
4. Reconnect the aligned backend to the existing extraction and SBOM generation adapter boundary.
5. Run backend comparison-focused regression tests and update attribution/dependency documentation.

Rollback strategy:
- Revert the backend isolation package and restore the current custom backend layer while keeping the outer CLI contract unchanged.
- Because the adapter boundary remains stable, rollback can target only the backend implementation surface.

## Open Questions

- Whether the best implementation mode is direct code transplant, heavy adaptation, or selective backend reimplementation from the reference design should be finalized during implementation after comparing package boundaries in the reference repository.
