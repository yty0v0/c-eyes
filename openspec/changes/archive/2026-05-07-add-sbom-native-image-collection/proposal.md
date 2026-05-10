## Why

The current `c-eyes sbom` capability only supports filesystem path collection and requires `-p/--path`, which does not fit native container-image collection targets such as daemon-managed images, image archives, and OCI layouts. We need to extend SBOM collection now so operators can collect package inventories from container images through native APIs and image formats without falling back to external command execution.

## What Changes

- Extend `c-eyes sbom` from path-only collection to support native container image collection targets.
- Keep SBOM as collection-only mode:
  - no risk-analysis chaining
  - no vulnerability/risk scoring behavior
  - no Trivy vulnerability database or severity output reuse
- Add explicit SBOM image target parameters for native image collection:
  - `--image <name>`
  - `--image-archive <tar>`
  - `--oci-layout <dir>`
- Preserve existing filesystem collection via `-p/--path`, but make all scan-target parameters mutually exclusive instead of always requiring `-p/--path`.
- Reuse only image content parsing and package inventory collection concepts from Trivy-style image handling, not its vulnerability analysis pipeline.
- Update SBOM help and validation behavior so users can discover image target modes and understand collection-only restrictions.

## Capabilities

### New Capabilities
- `sbom-image-collection`: Collect package inventory and SBOM content from native container image targets, including image references, local image archives, and OCI layout directories.

### Modified Capabilities
- `sbom-scan`: Expand SBOM command input model beyond required path-only scope and define mutually exclusive filesystem/image target modes while preserving collection-only behavior.
- `cli-help-prompts`: Update SBOM help output to document native image target parameters and target mutual-exclusion rules.

## Impact

- Affected code:
  - `cmd/edr` SBOM CLI parsing, validation, help text, and target dispatch
  - `internal/sbom` target resolution, image readers/adapters, and package inventory collection
  - test coverage for SBOM argument exclusivity and image target behavior
- Affected behavior:
  - `c-eyes sbom` can collect from filesystem paths and native image targets
  - `-p/--path` remains valid for filesystem mode but is no longer globally mandatory
  - image collection MUST avoid `docker/podman/ctr/nerdctl` external command execution
- Dependencies:
  - additional Go image/runtime libraries may be required for daemon, archive, and OCI collection support
