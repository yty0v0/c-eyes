## ADDED Requirements

### Requirement: CLI MUST provide environment variable scan command
The system SHALL provide an `edr environment-scan` command to collect environment variable metadata from Linux and Windows hosts and return normalized results.

#### Scenario: Default command execution
- **WHEN** the user runs `edr environment-scan` without optional filters
- **THEN** the system executes environment variable collection and returns a structured result payload

### Requirement: Collection MUST NOT invoke external command-line tools
The system MUST collect environment variable information via in-process OS APIs or direct system data source access, and MUST NOT invoke external command processes for this capability.

#### Scenario: Cross-platform collection path
- **WHEN** environment variable scan runs on Linux or Windows
- **THEN** the collector does not launch child processes for environment-variable enumeration

### Requirement: Query filters SHALL support requested parameters
The system SHALL support these optional filters: `groups` (integer array), `hostname` (fuzzy), `ip` (fuzzy), `key`, `value`, `user`, and `sysEnv` (boolean array).

#### Scenario: Fuzzy filters are applied
- **WHEN** the user provides `hostname` or `ip`
- **THEN** the system returns only records that match fuzzy rules for those fields

#### Scenario: Exact and array filters are combined
- **WHEN** the user provides any of `groups`, `key`, `value`, `user`, or `sysEnv`
- **THEN** the system returns only records satisfying all provided filter conditions

### Requirement: Output schema SHALL expose normalized host and environment fields
The system SHALL output records containing `displayIp`, `externalIpList`, `internalIpList`, `bizGroupId`, `bizGroup`, `remark`, `hostTagList`, `hostname`, `key`, `value`, `user`, and `sysEnv`.

#### Scenario: Contract keys are stable
- **WHEN** any environment-variable record is returned
- **THEN** all contract keys are present with `null` or empty-array fallback when source data is unavailable

### Requirement: Internal and external IP data MUST be list-based
The system MUST collect and output all available internal and external IP addresses as arrays, while keeping `displayIp` as a single display field.

#### Scenario: Multi-interface host IP mapping
- **WHEN** a host has multiple internal or external IP addresses
- **THEN** the output includes all values in `internalIpList` and `externalIpList`

### Requirement: Command SHALL support JSON and Excel outputs
The system SHALL support JSON output and Excel output for environment variable scan results.

#### Scenario: JSON output generation
- **WHEN** the user selects JSON output or uses default output
- **THEN** the system emits JSON records conforming to the output schema

#### Scenario: Excel output generation
- **WHEN** the user selects Excel output
- **THEN** the system generates an Excel file whose columns align with the defined output schema

### Requirement: Capability scope MUST remain information collection only
The system MUST limit this capability to collection and normalization of environment-variable metadata and MUST NOT include risk scoring, alert severity, or threat conclusions.

#### Scenario: No risk-analysis fields in result
- **WHEN** environment variable scan completes
- **THEN** the output contains asset metadata only and excludes risk verdict fields
