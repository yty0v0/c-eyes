## MODIFIED Requirements

### Requirement: SBOM image collection SHALL support native image reference targets
The system SHALL support `--image <name>` as an SBOM collection target for native container image collection. This mode MUST use a backend architecture aligned as closely as practical to the reference tool's image-source implementation, while preserving the current project's CLI and collection-only SBOM behavior.

#### Scenario: Image reference uses native collection path
- **WHEN** the user executes `c-eyes sbom --image nginx:1.27`
- **THEN** the collection path does not spawn `docker`, `podman`, `ctr`, or `nerdctl` external commands

#### Scenario: Unsupported native runtime returns explicit error
- **WHEN** the user executes `c-eyes sbom --image <name>` in an environment where no supported native image backend is available
- **THEN** the command returns an explicit English runtime error indicating native image collection is unavailable
- **AND** the error identifies the attempted backend states, including backend-specific diagnostics for aligned runtime sources
