## Why

`c-eyes sbom --image` already supports native Docker, Podman, and remote-registry attempts, but it still cannot read images from local containerd stores. In environments where containerd is the primary runtime, this leaves image-reference SBOM collection incomplete even though the rest of the native image pipeline is already in place.

## What Changes

- Add native containerd backend support to `c-eyes sbom --image`.
- Keep the existing backend order and collection-only scope intact while inserting containerd as another native image source.
- Support local image lookup from containerd socket-backed image stores without invoking `ctr` or other external commands.
- Export containerd-managed images through native APIs and reuse the existing SBOM image extraction/generation flow.
- Surface explicit English errors when containerd is unavailable, image lookup fails, or namespace/socket resolution is invalid.

## Capabilities

### New Capabilities
- `sbom-containerd-image-backend`: Resolve `c-eyes sbom --image` targets from native containerd image stores and feed them into the existing SBOM image pipeline.

### Modified Capabilities
- `sbom-scan`: Extend native image-reference collection to include containerd-backed image sources in addition to existing Docker/Podman/remote behavior.

## Impact

- Affected code:
  - `internal/sbom` native image backend selection and containerd export plumbing
  - `cmd/edr` SBOM image-reference tests and user-visible error behavior
- Affected behavior:
  - `--image` gains containerd-native lookup/export support
  - failure diagnostics for image-reference mode include containerd-specific backend state
- Dependencies:
  - add Go-native containerd client/export dependencies compatible with the current toolchain and build targets
