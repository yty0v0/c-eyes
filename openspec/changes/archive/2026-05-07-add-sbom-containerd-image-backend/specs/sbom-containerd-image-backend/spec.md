## ADDED Requirements

### Requirement: SBOM image collection SHALL support native containerd image lookup
The system SHALL support resolving `c-eyes sbom --image <name>` targets from local containerd image stores through native containerd APIs. This backend MUST NOT invoke `ctr` or other external command-line tools.

#### Scenario: Containerd image reference uses native lookup path
- **WHEN** the user executes `c-eyes sbom --image <name>` and the image exists in a reachable containerd image store
- **THEN** the system resolves the image through native containerd APIs
- **AND** the collection path does not spawn `ctr` or other external commands

### Requirement: Containerd-resolved images SHALL reuse the common SBOM image pipeline
Images resolved from containerd SHALL be exported through native containerd APIs and routed into the same merged-rootfs extraction and SBOM inventory pipeline used by other image backends.

#### Scenario: Containerd image produces standard SBOM payload
- **WHEN** the user executes `c-eyes sbom --image <name>` and containerd successfully resolves the image
- **THEN** the resulting SBOM output follows the normal `sbom` document contract
- **AND** the output does not introduce vulnerability or risk-analysis fields

### Requirement: Containerd backend SHALL expose explicit environment-aware resolution errors
When containerd backend resolution fails, the system SHALL return explicit English diagnostics indicating whether socket discovery, namespace resolution, image lookup, or image export failed.

#### Scenario: Containerd socket unavailable
- **WHEN** the image-reference mode reaches the containerd backend and no usable containerd socket is available
- **THEN** the backend error message explicitly states that the containerd socket is unavailable

#### Scenario: Containerd image lookup misses target
- **WHEN** the image-reference mode reaches the containerd backend but the requested image does not exist in the selected containerd namespace
- **THEN** the backend error message explicitly states that the image could not be found in containerd
