# sbom-scan Specification

## Purpose
TBD - created by archiving change add-sbom-module. Update Purpose after archive.
## Requirements
### Requirement: SBOM command SHALL provide collection-only software bill-of-materials scanning
The system SHALL provide a top-level `c-eyes sbom` command that runs SBOM information collection on supported platforms and SHALL NOT enable risk-analysis chaining for this command.

#### Scenario: Run SBOM collection successfully
- **WHEN** the user executes `c-eyes sbom -p <path>`
- **THEN** the system performs SBOM information collection and produces SBOM output rows/documents

#### Scenario: Reject risk-analysis flag for SBOM command
- **WHEN** the user executes `c-eyes sbom -r`
- **THEN** the command returns an English argument error indicating `sbom` is collection-only and does not support `-r/--riskanalyze`

### Requirement: SBOM command SHALL require explicit scan scope path
The system SHALL require `-p/--path` for `c-eyes sbom` so scan scope is explicit and reproducible.

#### Scenario: Reject missing scan path
- **WHEN** the user executes `c-eyes sbom` without `-p/--path`
- **THEN** the command returns an English argument error indicating `-p/--path` is required for `sbom`

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

