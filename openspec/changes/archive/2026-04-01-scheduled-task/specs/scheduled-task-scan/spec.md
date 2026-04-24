## ADDED Requirements

### Requirement: CLI MUST provide scheduled task collection command
The system SHALL provide an `edr scheduled-task-scan` command to collect scheduled task metadata from endpoints and return normalized results.

#### Scenario: Default execution returns records
- **WHEN** the user runs `edr scheduled-task-scan` without additional filters
- **THEN** the system executes scheduled task collection and returns structured results

### Requirement: Collection MUST avoid external command execution
The system MUST collect scheduled task information through in-process OS APIs or direct data source parsing, and MUST NOT invoke external command-line tools.

#### Scenario: Cross-platform collection path constraint
- **WHEN** scheduled task collection runs on Windows or Linux
- **THEN** no child process is launched for task enumeration commands

### Requirement: Query filters SHALL support requested parameters
The system SHALL support these optional filters: `groups` (integer array), `hostname` (fuzzy), `ip` (fuzzy), `user` (string array), `execPath`, `conf`, `taskTime` (date range), and `taskType`.

#### Scenario: Fuzzy host filters are applied
- **WHEN** the user provides `hostname` or `ip`
- **THEN** the system returns only records that match fuzzy rules for those fields

#### Scenario: Structured filters are combined
- **WHEN** the user provides `groups`, `user`, `taskTime`, or `taskType`
- **THEN** the system returns only records satisfying all provided filter conditions

### Requirement: Task type domain MUST be constrained
The system MUST restrict `taskType` values to `CRONTAB`, `AT`, and `BATCH`.

#### Scenario: Unsupported task type is rejected
- **WHEN** the user provides a `taskType` outside `CRONTAB|AT|BATCH`
- **THEN** the command exits with validation error and non-zero status

### Requirement: Output schema SHALL expose normalized host and task fields
The system SHALL output records containing: `displayIp`, `externalIpList`, `internalIpList`, `bizGroupId`, `bizGroup`, `remark`, `hostTagList`, `hostname`, `user`, `execTime`, `execPath`, `conf`, `taskTime`, `taskId`, `taskType`, and `crondOpen`.

#### Scenario: Contract keys are stable
- **WHEN** any scheduled task record is returned
- **THEN** all contract keys are present with null or empty-array fallback when data is unavailable

### Requirement: Internal and external IP data MUST be list-based
The system MUST collect and output all available internal and external IP addresses as arrays, while preserving `displayIp` as a single display field.

#### Scenario: Multi-interface host IP mapping
- **WHEN** a host has multiple internal or external IP addresses
- **THEN** the output includes full values in `internalIpList` and `externalIpList`

### Requirement: Command SHALL support JSON and Excel outputs
The system SHALL support JSON output and Excel output for scheduled task scan results.

#### Scenario: JSON output path
- **WHEN** the user selects JSON output or uses default output
- **THEN** the system emits JSON records conforming to the output schema

#### Scenario: Excel output path
- **WHEN** the user selects Excel output
- **THEN** the system generates an Excel file containing contract columns for scheduled task records

### Requirement: Capability scope MUST remain information collection only
The system MUST limit this capability to collection and normalization of scheduled task metadata and MUST NOT include risk scoring, alert severity, or threat conclusions.

#### Scenario: No risk-analysis fields in results
- **WHEN** scheduled task scan completes
- **THEN** the output contains asset metadata only and excludes risk verdict fields
