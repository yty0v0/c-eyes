## Why

The current `c-eyes sbom` image pipeline now supports native backends for Docker, Podman, containerd, archives, and OCI layouts, but it still uses a project-local hand-rolled backend layer. That gets the feature working, yet it remains behind the reference tool in backend maturity, metadata handling, compatibility coverage, and long-term maintainability. We need a dedicated alignment change now so the image backend layer itself tracks a proven implementation model instead of continuing to diverge through incremental reimplementation.

## What Changes

- Replace the current hand-rolled SBOM image backend layer with an implementation aligned as closely as practical to the reference tool's image backend architecture.
- Reuse or adapt the reference tool's image-source logic for:
  - image reference parsing
  - Docker / Podman / containerd / remote resolution
  - archive / OCI layout loading
  - native image export and rootfs extraction flow
- Keep `c-eyes sbom` collection-only:
  - no vulnerability scanning
  - no vulnerability database setup
  - no risk/severity output
- Preserve the current `c-eyes sbom` public CLI contract and output shape while swapping the backend implementation under it.
- Add attribution / dependency hygiene for any imported or adapted backend code.

## Capabilities

### New Capabilities
- `sbom-image-backend-alignment`: Align SBOM image backend behavior and architecture with the reference tool while preserving the host project's command and output contracts.

### Modified Capabilities
- `sbom-scan`: Refine the internal implementation contract of image-source handling so the command uses a reference-aligned backend layer rather than a project-local ad hoc backend implementation.

## Impact

- Affected code:
  - `internal/sbom` image backend and extraction packages
  - dependency and attribution surface for imported/adapted backend logic
  - image-mode tests and compatibility validation
- Affected behavior:
  - public CLI and collection-only boundary remain stable
  - backend success/error semantics should become closer to the reference tool
  - future image-source maintenance should become easier because the architecture is less bespoke
