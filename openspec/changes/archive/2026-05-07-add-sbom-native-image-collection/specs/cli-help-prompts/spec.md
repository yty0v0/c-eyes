## MODIFIED Requirements

### Requirement: SBOM help SHALL use English structured subcommand template
The system SHALL provide English help for `c-eyes sbom` with structured sections and option descriptions consistent with other unified modules.

#### Scenario: SBOM subcommand help uses standard sections
- **WHEN** the user executes `c-eyes sbom -h`
- **THEN** help output includes `NAME`, `USAGE`, and `OPTIONS`
- **AND** options include target selectors `-p/--path`, `--image`, `--image-archive`, `--oci-layout`, and `--format` with values `xspdx-json|spdx-json`

#### Scenario: SBOM help states collection-only behavior
- **WHEN** the user executes `c-eyes sbom -h`
- **THEN** help text states SBOM is collection-only and does not support `-r/--riskanalyze`

#### Scenario: SBOM help states target exclusivity behavior
- **WHEN** the user executes `c-eyes sbom -h`
- **THEN** help text states exactly one target selector must be provided
- **AND** help text explains that path and image target parameters are mutually exclusive
