## Context

The previous SBOM image collection change established a shared image pipeline for `--image-archive`, `--oci-layout`, and `--image`, with native backend attempts for Docker, Podman, and remote registry resolution. Containerd was intentionally deferred because it introduced a heavier dependency surface and required separate evaluation.

We now know the remaining gap precisely: `--image` should also be able to resolve images from a local containerd store using native APIs, not by shelling out to `ctr`. The existing implementation already knows how to:
- turn a native image backend into a `v1.Image`
- extract merged rootfs content into a temporary directory
- run the standard SBOM inventory flow on that directory

This change is therefore a narrow backend-extension change, not a rewrite of the image pipeline.

Constraints:
- preserve collection-only SBOM behavior
- do not break current archive/OCI/Docker/Podman/remote paths
- avoid external command execution
- stay within a Go/toolchain/dependency set that works for the current project

## Goals / Non-Goals

**Goals:**
- add a native containerd backend to `c-eyes sbom --image`
- resolve local image references from containerd stores through socket/client APIs
- export resolved containerd images into the existing extraction pipeline
- return backend-specific English errors when containerd is unavailable or the image cannot be found

**Non-Goals:**
- add `ctr` command execution fallback
- redesign the existing image extraction pipeline
- change archive/OCI/Docker/Podman/remote backend semantics
- expand SBOM scope into vulnerability analysis

## Decisions

### Decision 1: Treat containerd as a backend for existing `--image` mode, not as a new user-facing flag
- Decision: containerd support SHALL plug into the existing `--image` backend chain rather than introducing a new public CLI flag.
- Rationale: The current CLI already models image references as a backend-agnostic target. Adding a new user flag would complicate the command surface without improving operator intent.
- Alternatives considered:
  - Add `--containerd-image`: rejected because it leaks backend selection into the common path unnecessarily.

### Decision 2: Reuse native client/export flow and existing merged-rootfs extraction
- Decision: containerd integration SHALL resolve the image through the native client, export the image content through containerd APIs, and then reuse the existing `extractImageToTempRoot` flow.
- Rationale: This minimizes change size and keeps all image-source modes converging on one extraction/inventory path.
- Alternatives considered:
  - Write a separate containerd-specific filesystem walker: rejected because it would duplicate downstream logic.

### Decision 3: Resolve containerd connection settings through environment-aware defaults
- Decision: containerd backend SHALL first honor explicit environment overrides, then fall back to standard socket and namespace defaults.
- Rationale: This matches how operators commonly wire containerd and keeps the backend usable in different environments without changing the public CLI.
- Alternatives considered:
  - Hardcode one socket only: rejected because it is brittle across environments.

### Decision 4: Keep backend diagnostics explicit and ordered
- Decision: image-reference failures SHALL continue to report attempted backends in order, now including containerd-specific failure messages.
- Rationale: The current multi-backend error chain is one of the main operator aids when native image collection cannot resolve a reference.

## Risks / Trade-offs

- [Risk] Containerd adds a larger dependency surface than the previous backends.
  -> Mitigation: restrict the change to the minimal client/export APIs needed for local image resolution and avoid broad dependency churn.

- [Risk] Containerd socket and namespace layouts vary by environment.
  -> Mitigation: use explicit environment-aware defaults and return backend-specific diagnostics when lookup fails.

- [Risk] Introducing containerd could destabilize already passing image backends.
  -> Mitigation: keep the implementation additive, add targeted backend tests, and re-run focused SBOM/CLI regressions.

## Migration Plan

1. Add OpenSpec delta requirements for containerd backend support.
2. Integrate minimal containerd client/export plumbing into `internal/sbom` image backend selection.
3. Reuse existing image extraction and SBOM generation flow for containerd-resolved images.
4. Add tests for backend ordering/error reporting and focused validation.
5. Re-run OpenSpec validation and targeted Go tests.

Rollback strategy:
- Remove the containerd-specific backend branch while leaving existing Docker/Podman/remote/archive/OCI paths unchanged.
- Because the change is additive to backend selection, rollback is isolated and low-risk.

## Open Questions

- Whether future work should expose explicit containerd configuration flags beyond environment-driven resolution remains open, but is not required for this change.
