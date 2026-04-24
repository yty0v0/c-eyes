## ADDED Requirements

### Requirement: CLI MUST provide jar package collection command
The system SHALL provide an `edr jar-package-scan` command to collect jar package metadata from Windows and Linux endpoints and return normalized records.

#### Scenario: Default execution returns records
- **WHEN** the user runs `edr jar-package-scan` without optional filters
- **THEN** the system executes jar package metadata collection and returns structured records

### Requirement: Collection MUST avoid external command execution
The system MUST collect jar package information through in-process OS APIs, file-system inspection, metadata parsing, and runtime correlation, and MUST NOT invoke external command-line tools during collection.

#### Scenario: Cross-platform non-command collection
- **WHEN** collection runs on Windows or Linux
- **THEN** no child process is launched for jar package enumeration commands

### Requirement: Collection strategy SHALL combine static and dynamic signals
The system SHALL use a static-plus-dynamic approach to identify jar package records, including static artifacts (directory structure, package filenames, manifest metadata) and dynamic runtime association.

#### Scenario: Static and dynamic data are merged
- **WHEN** static and runtime sources both provide package evidence for the same host asset
- **THEN** the system merges them into normalized records with conflict resolution and deduplication

### Requirement: Query filters SHALL support requested parameters
The system SHALL support these optional request filters: `groups` (integer array), `hostname` (fuzzy string), `ip` (fuzzy string), `name` (fuzzy string), `version` (string array), `type` (integer array), `executable` (boolean array), and `path` (fuzzy string).

#### Scenario: Fuzzy filters are applied
- **WHEN** the user provides `hostname`, `ip`, `name`, or `path`
- **THEN** the system returns only records that satisfy fuzzy matching for provided fields

#### Scenario: Structured filters are combined
- **WHEN** the user provides any of `groups`, `version`, `type`, or `executable`
- **THEN** the system returns only records satisfying all provided structured filter conditions

### Requirement: Package type filter MUST support defined domain values
The system MUST accept `type` filter values `1`, `2`, `3`, and `8`, representing application package, system package, web-service bundled package, and other dependency package.

#### Scenario: Type domain validation
- **WHEN** the user submits a `type` value outside `1`, `2`, `3`, or `8`
- **THEN** the command exits with a validation error and a non-zero status

### Requirement: Output schema SHALL expose normalized jar package fields
The system SHALL output records containing stable keys: `displayIp`, `externalIpList`, `internalIpList`, `bizGroupId`, `bizGroup`, `remark`, `hostTagList`, `hostname`, `name`, `version`, `type`, `executable`, and `path`.

#### Scenario: Contract keys are stable
- **WHEN** any jar package record is returned
- **THEN** all contract keys are present with null or empty-array fallback when data is unavailable

### Requirement: IP collection MUST be list-based for internal and external addresses
The system MUST collect and output all available internal and external IP addresses as arrays, while preserving `displayIp` as a single display field.

#### Scenario: Multi-interface host address coverage
- **WHEN** a host has multiple internal or external addresses
- **THEN** the output includes full values in `internalIpList` and `externalIpList`

### Requirement: Command SHALL support JSON and Excel outputs
The system SHALL support JSON and Excel output formats for jar package scan results with UTF-8 compatible content.

#### Scenario: JSON output path
- **WHEN** the user selects JSON output or uses default output
- **THEN** the system emits JSON records conforming to the output schema

#### Scenario: Excel output path
- **WHEN** the user selects Excel output
- **THEN** the system generates an Excel file containing contract-aligned columns for jar package records

### Requirement: Capability scope MUST remain information collection only
The system MUST limit this capability to collection and normalization of jar package metadata and MUST NOT include risk scoring, risk level assessment, vulnerability judgment, or threat conclusions.

#### Scenario: No risk-analysis fields in results
- **WHEN** jar package scan completes
- **THEN** the output contains inventory metadata only and excludes risk verdict fields
