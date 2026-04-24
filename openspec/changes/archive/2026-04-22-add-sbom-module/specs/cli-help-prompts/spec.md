## ADDED Requirements

### Requirement: Root help SHALL include sbom command entry
When users run root help, the command listing SHALL include `sbom` as a first-class module command.

#### Scenario: Root help lists sbom command
- **WHEN** the user executes `c-eyes -h`
- **THEN** the `COMMANDS` section includes `sbom`
- **AND** `sbom` description indicates software bill-of-materials collection capability

### Requirement: SBOM help SHALL use English structured subcommand template
The system SHALL provide English help for `c-eyes sbom` with structured sections and option descriptions consistent with other unified modules.

#### Scenario: SBOM subcommand help uses standard sections
- **WHEN** the user executes `c-eyes sbom -h`
- **THEN** help output includes `NAME`, `USAGE`, and `OPTIONS`
- **AND** options include required `-p/--path` and `--format` with values `xspdx-json|spdx-json`

#### Scenario: SBOM help states collection-only behavior
- **WHEN** the user executes `c-eyes sbom -h`
- **THEN** help text states SBOM is collection-only and does not support `-r/--riskanalyze`

#### Scenario: SBOM help states required path behavior
- **WHEN** the user executes `c-eyes sbom -h`
- **THEN** help text states `-p/--path` is required to define scan scope
