## MODIFIED Requirements

### Requirement: SBOM image collection SHALL support native image reference targets
The system SHALL support `--image <name>` as an SBOM collection target for native container image collection. This mode MUST use native runtime or registry access mechanisms rather than external command execution, including Docker, Podman, containerd, and remote-registry resolution paths where available.

#### Scenario: Image reference uses native collection path
- **WHEN** the user executes `c-eyes sbom --image nginx:1.27`
- **THEN** the collection path does not spawn `docker`, `podman`, `ctr`, or `nerdctl` external commands

#### Scenario: Unsupported native runtime returns explicit error
- **WHEN** the user executes `c-eyes sbom --image <name>` in an environment where no supported native image backend is available
- **THEN** the command returns an explicit English runtime error indicating native image collection is unavailable
- **AND** the error identifies the attempted backend states, including containerd when that backend is evaluated
