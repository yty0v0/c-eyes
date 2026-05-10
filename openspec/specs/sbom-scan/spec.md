# sbom-scan Specification

## Purpose
TBD - created by archiving change add-sbom-module. Update Purpose after archive.
## Requirements
### Requirement: SBOM command SHALL provide collection-only software bill-of-materials scanning
The system SHALL provide a top-level `c-eyes sbom` command that runs SBOM information collection on supported platforms and SHALL NOT enable risk-analysis chaining for this command.

#### Scenario: Run filesystem SBOM collection successfully
- **WHEN** the user executes `c-eyes sbom -p <path>`
- **THEN** the system performs SBOM information collection and produces SBOM output rows/documents

#### Scenario: Reject risk-analysis flag for SBOM command
- **WHEN** the user executes `c-eyes sbom -r`
- **THEN** the command returns an English argument error indicating `sbom` is collection-only and does not support `-r/--riskanalyze`

### Requirement: SBOM command SHALL require explicit scan target selection
The system SHALL require exactly one explicit scan target selector for `c-eyes sbom`. Accepted selectors are `-p/--path` and `--image-target`, and these selectors MUST be mutually exclusive.

#### Scenario: Reject missing SBOM target
- **WHEN** the user executes `c-eyes sbom` without `-p/--path` or `--image-target`
- **THEN** the command returns an English argument error indicating one explicit SBOM target is required

#### Scenario: Reject multiple target selectors
- **WHEN** the user executes `c-eyes sbom -p <path> --image-target nginx:1.27`
- **THEN** the command returns an English argument error indicating SBOM target selectors are mutually exclusive

#### Scenario: Reject target type when using filesystem path mode
- **WHEN** the user executes `c-eyes sbom -p <path> --target-type archive`
- **THEN** the command returns an English argument error indicating `--target-type` cannot be used with `-p/--path`

#### Scenario: Reject standalone target type
- **WHEN** the user executes `c-eyes sbom --target-type image`
- **THEN** the command returns an English argument error indicating `--target-type` requires `--image-target`

### Requirement: SBOM command SHALL support standards format selection
The system SHALL support SBOM content format selection through command options, with accepted values `xspdx-json` and `spdx-json`, and SHALL use `xspdx-json` as default when not specified.

#### Scenario: Use default xspdx format
- **WHEN** the user executes `c-eyes sbom -p <path>` without specifying format
- **THEN** the generated SBOM document format is `xspdx-json`

#### Scenario: Use spdx-json format explicitly
- **WHEN** the user executes `c-eyes sbom -p <path> --format spdx-json`
- **THEN** the generated SBOM document format is `spdx-json`

#### Scenario: Reject unsupported format value
- **WHEN** the user executes `c-eyes sbom -p <path> --format cyclonedx-json`
- **THEN** the command returns an English argument error listing supported values `xspdx-json` and `spdx-json`

### Requirement: SBOM image collection SHALL support unified image target selection
The system SHALL support `--image-target <value>` as the user-facing image collection selector for native container image collection. This mode MUST use a backend architecture aligned as closely as practical to the reference tool's image-source implementation, while preserving the current project's CLI and collection-only SBOM behavior.

#### Scenario: Accept image reference target through unified image selector
- **WHEN** the user executes `c-eyes sbom --image-target nginx:1.27`
- **THEN** the system treats the request as native image collection instead of filesystem path collection

#### Scenario: Explicit image target type overrides auto-detection
- **WHEN** the user executes `c-eyes sbom --image-target D:\\images\\nginx.tar --target-type archive`
- **THEN** the system forces archive mode instead of performing automatic target-type detection

#### Scenario: Image reference uses native collection path
- **WHEN** the user executes `c-eyes sbom --image-target nginx:1.27`
- **THEN** the collection path does not spawn `docker`, `podman`, `ctr`, or `nerdctl` external commands

#### Scenario: Unsupported native runtime returns explicit error
- **WHEN** the user executes `c-eyes sbom --image-target <value>` in an environment where no supported native image backend is available
- **THEN** the command returns an explicit English runtime error indicating native image collection is unavailable
- **AND** the error identifies the attempted backend states, including backend-specific diagnostics for aligned runtime sources

### Requirement: SBOM image collection SHALL support local image archives
The system SHALL support local container image archives through `--image-target <value>` automatic detection and `--target-type archive` explicit selection.

#### Scenario: Scan image archive tarball
- **WHEN** the user executes `c-eyes sbom --image-target D:\\images\\nginx.tar`
- **THEN** the system reads the archive contents directly and produces SBOM output from the contained image inventory

### Requirement: SBOM image collection SHALL support OCI layout directories
The system SHALL support OCI image layout directories through `--image-target <value>` automatic detection and `--target-type oci-layout` explicit selection.

#### Scenario: Scan OCI layout directory
- **WHEN** the user executes `c-eyes sbom --image-target D:\\images\\nginx-oci`
- **THEN** the system reads OCI layout metadata and blob content directly and produces SBOM output from the contained image inventory

### Requirement: SBOM image collection SHALL remain inventory-only
Native image collection under `c-eyes sbom` MUST only reuse image content parsing and package inventory collection capabilities. It MUST NOT add vulnerability matching, severity classification, or risk-analysis output to the SBOM command.

#### Scenario: Image SBOM output omits vulnerability verdicts
- **WHEN** the user executes any SBOM image collection mode
- **THEN** the resulting output contains software inventory/SBOM document content only
- **AND** the output does not include vulnerability, risk score, or risk level fields
