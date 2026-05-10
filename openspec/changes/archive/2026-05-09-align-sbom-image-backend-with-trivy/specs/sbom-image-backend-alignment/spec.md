## ADDED Requirements

### Requirement: SBOM image backend SHALL align to the reference tool's source-resolution architecture
The system SHALL implement SBOM image-source handling using a backend architecture aligned as closely as practical to the reference tool's image backend design, including native handling for archive, OCI layout, daemon-backed image references, and remote-registry resolution.

#### Scenario: Backend alignment preserves multi-source image resolution
- **WHEN** the user executes any supported SBOM image collection mode
- **THEN** the backend follows a reference-aligned source-resolution flow rather than a project-local ad hoc backend path

### Requirement: Backend alignment SHALL preserve the host project's collection-only contract
Reference-aligned backend logic MUST stop at image/rootfs acquisition and MUST NOT import vulnerability analysis, vulnerability database setup, or risk/severity reporting into the `c-eyes sbom` command.

#### Scenario: Reference-aligned backend remains inventory-only
- **WHEN** the aligned backend resolves and extracts an image successfully
- **THEN** the resulting SBOM output contains software inventory/SBOM document content only
- **AND** the command does not emit vulnerability or risk-analysis fields

### Requirement: Backend-aligned code SHALL remain behind a stable adapter boundary
The system SHALL isolate reference-aligned backend logic behind a stable internal adapter boundary that feeds the existing SBOM generation pipeline.

#### Scenario: SBOM generation flow remains stable after backend replacement
- **WHEN** backend implementation changes from custom logic to reference-aligned logic
- **THEN** the outer `c-eyes sbom` command contract and SBOM document-generation flow remain unchanged
