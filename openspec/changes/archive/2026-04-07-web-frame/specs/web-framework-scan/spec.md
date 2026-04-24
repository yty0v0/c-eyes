## ADDED Requirements

### Requirement: CLI MUST provide web framework collection command
The system SHALL provide an `edr web-framework-scan` command to collect web framework metadata from Windows and Linux endpoints and return normalized records.

#### Scenario: Default execution returns records
- **WHEN** the user runs `edr web-framework-scan` without optional filters
- **THEN** the system executes framework metadata collection and returns structured records

### Requirement: Collection MUST avoid external command execution
The system MUST collect web framework information through in-process OS APIs, configuration parsing, file-system inspection, and runtime metadata correlation, and MUST NOT invoke external command-line tools during collection.

#### Scenario: Cross-platform non-command collection
- **WHEN** collection runs on Windows or Linux
- **THEN** no child process is launched for framework enumeration commands

### Requirement: Collection strategy SHALL combine static and dynamic signals
The system SHALL use a static-plus-dynamic approach to identify framework records, including static artifacts (configuration files, deployment paths, metadata files) and dynamic runtime association.

#### Scenario: Static and dynamic data are merged
- **WHEN** static and runtime sources both provide framework evidence for the same host asset
- **THEN** the system merges them into normalized records with conflict resolution and deduplication

### Requirement: Query filters SHALL support requested parameters
The system SHALL support these optional request filters: `groups` (integer array), `hostname` (fuzzy string), `ip` (fuzzy string), `name` (fuzzy string), `version` (string), `type` (string array), and `serverName` (string array).

#### Scenario: Fuzzy filters are applied
- **WHEN** the user provides `hostname`, `ip`, or `name`
- **THEN** the system returns only records that satisfy fuzzy matching for provided fields

#### Scenario: Structured filters are combined
- **WHEN** the user provides any of `groups`, `version`, `type`, or `serverName`
- **THEN** the system returns only records satisfying all provided structured filter conditions

### Requirement: Output schema SHALL expose normalized framework fields
The system SHALL output records containing stable keys: `displayIp`, `externalIpList`, `internalIpList`, `bizGroupId`, `bizGroup`, `remark`, `hostTagList`, `hostname`, `name`, `version`, `type`, `serverName`, `domainName`, `webAppDir`, `jarCount`, `jarList`, `webRoot`, and `workDir`.

#### Scenario: Contract keys are stable
- **WHEN** any web framework record is returned
- **THEN** all contract keys are present with null or empty-array fallback when data is unavailable

### Requirement: IP collection MUST be list-based for internal and external addresses
The system MUST collect and output all available internal and external IP addresses as arrays, while preserving `displayIp` as a single display field.

#### Scenario: Multi-interface host address coverage
- **WHEN** a host has multiple internal or external addresses
- **THEN** the output includes full values in `internalIpList` and `externalIpList`

### Requirement: Jar metadata MUST follow normalized sub-schema
The system MUST represent `jarList` as a list of objects where each object includes `version`, `absDir`, and `jarName`, and MUST provide `jarCount` as the total associated jar package count.

#### Scenario: Jar details are normalized
- **WHEN** associated jar packages are detected for a framework record
- **THEN** each jar entry is emitted with `version`, `absDir`, and `jarName`, and `jarCount` reflects the list size

### Requirement: Command SHALL support JSON and Excel outputs
The system SHALL support JSON and Excel output formats for web framework scan results with UTF-8 compatible content.

#### Scenario: JSON output path
- **WHEN** the user selects JSON output or uses default output
- **THEN** the system emits JSON records conforming to the output schema

#### Scenario: Excel output path
- **WHEN** the user selects Excel output
- **THEN** the system generates an Excel file containing contract-aligned columns for framework records

### Requirement: Capability scope MUST remain information collection only
The system MUST limit this capability to collection and normalization of web framework metadata and MUST NOT include risk scoring, risk level assessment, vulnerability judgment, or threat conclusions.

#### Scenario: No risk-analysis fields in results
- **WHEN** web framework scan completes
- **THEN** the output contains inventory metadata only and excludes risk verdict fields
