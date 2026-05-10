## Context

The existing `sbom-scan` capability is modeled as a collection-only command that requires `-p/--path` and emits SBOM JSON documents. That model works for filesystem scans but does not cover native image targets, where the scan subject may be a daemon-managed image reference, a local image archive tarball, or an OCI layout directory.

We already confirmed that Trivy-style image collection provides a better architectural reference than `osv-scanner-main` for native image support because it reads image content through daemon APIs, sockets, archives, and OCI layouts instead of spawning external commands. The change must keep SBOM strictly in information-collection scope: image parsing and package inventory only, with no vulnerability matching, scoring, or cloud database behavior.

Constraints:
- Keep `sbom` collection-only and incompatible with `-r/--riskanalyze`
- Preserve existing filesystem mode compatibility where reasonable
- Avoid external command execution for image collection paths
- Support Windows and Linux
- Keep SBOM output JSON-only per existing `global-output` contract

## Goals / Non-Goals

**Goals:**
- Add native image collection inputs to `c-eyes sbom`
- Preserve filesystem path collection with explicit target semantics
- Model scan targets as mutually exclusive options:
  - `-p/--path`
  - `--image`
  - `--image-archive`
  - `--oci-layout`
- Reuse only image content parsing and package inventory collection behavior from Trivy-like architecture
- Ensure help text and validation explain target exclusivity and collection-only behavior

**Non-Goals:**
- Reuse or embed Trivy vulnerability scanning, DB initialization, or severity outputs
- Add chained risk-analysis support to `sbom`
- Guarantee full parity with every Trivy image source in the first implementation phase
- Introduce CSV/XLSX SBOM exports

## Decisions

### Decision 1: Separate filesystem and image targets through explicit mutually exclusive flags
- Decision: `c-eyes sbom` SHALL support exactly one target selector per run: `-p/--path`, `--image`, `--image-archive`, or `--oci-layout`.
- Rationale: A filesystem path and an image reference have different semantics, validation paths, and backends. Explicit target parameters keep the CLI understandable and prevent ambiguous interpretation.
- Alternatives considered:
  - Keep `-p/--path` mandatory for all modes: rejected because native image references are not naturally path-based.
  - Overload `-p/--path` to accept both paths and image names: rejected because it blurs validation and user intent.

### Decision 2: Keep `-p/--path` for filesystem mode, but remove path-only global requirement
- Decision: `-p/--path` remains required only when filesystem mode is selected.
- Rationale: Preserves existing local path workflow while allowing first-class image targets.
- Alternatives considered:
  - Deprecate `-p/--path`: rejected because current filesystem SBOM behavior is already established and still valuable.

### Decision 3: Adopt native image collection architecture only
- Decision: Image collection SHALL use native APIs/file formats and MUST NOT invoke `docker`, `podman`, `ctr`, `nerdctl`, or equivalent external commands.
- Rationale: This matches the confirmed requirement for native collection, reduces deployment assumptions, and aligns with Trivy's stronger architecture for daemon/archive/OCI handling.
- Alternatives considered:
  - Shell out to Docker/Podman commands for image export: rejected because it violates the native-collection requirement.

### Decision 4: Stage image-source support by stability
- Decision: The change SHALL define three user-visible target modes now (`--image`, `--image-archive`, `--oci-layout`), but implementation planning may prioritize archive and OCI readers plus the most stable daemon integration first.
- Rationale: The user-visible contract should be explicit, but runtime backends vary in cross-platform complexity. Staging reduces implementation risk without weakening the target model.
- Alternatives considered:
  - Promise every runtime/backend at identical depth immediately: rejected because it expands risk and slows delivery.

### Decision 5: Scope SBOM image integration to content parsing and package inventory only
- Decision: The integrated image pipeline SHALL stop at image metadata reading, layer/content traversal, and package inventory extraction required for SBOM generation.
- Rationale: Keeps capability boundaries clean and avoids turning `sbom` into a vulnerability scanner.
- Alternatives considered:
  - Include Trivy vulnerability/report pipeline under `sbom`: rejected because it conflicts with collection-only scope and existing module boundaries.

## Risks / Trade-offs

- [Risk] Native daemon integrations differ by platform and environment availability.
  -> Mitigation: Define stable CLI target contracts first, then implement backends with explicit unsupported-environment errors where needed.

- [Risk] Target exclusivity changes the current assumption that SBOM always requires `-p/--path`.
  -> Mitigation: Update `sbom-scan` and help specs together so parser behavior, usage text, and tests stay aligned.

- [Risk] Reusing image parsing concepts from Trivy may introduce new dependencies and maintenance surface.
  -> Mitigation: Wrap image loading behind narrow internal adapters and keep vulnerability logic out of the integration surface.

- [Risk] `--image` mode may be interpreted as requiring every runtime/backend on day one.
  -> Mitigation: Document that the command contract is stable while backend coverage may vary by supported environment and native integration availability.

## Migration Plan

1. Update OpenSpec requirements for SBOM target model and help behavior.
2. Refactor SBOM argument parsing to accept one mutually exclusive target selector.
3. Introduce internal image-target adapters for archive, OCI layout, and native image reference loading.
4. Route image-derived package inventories into existing SBOM generation flow.
5. Add parser/help/tests for target exclusivity and collection-only scope.
6. Validate resulting OpenSpec change and implementation tests.

Rollback strategy:
- Revert image-target parsing and adapter wiring while preserving current `-p/--path` filesystem mode.
- Because the change is additive around target handling, rollback can be isolated to SBOM-specific parser and integration branches.

## Open Questions

- Whether `--image` mode should initially guarantee only Docker daemon support or declare broader runtime compatibility from the first implementation is still an implementation-planning question, but it does not block artifact creation.
