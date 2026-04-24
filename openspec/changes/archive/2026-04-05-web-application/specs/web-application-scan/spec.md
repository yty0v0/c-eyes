## ADDED Requirements

### Requirement: CLI MUST provide web application collection command
The system SHALL provide an `edr web-application-scan` command to collect web application metadata from Windows and Linux endpoints and return normalized results.

#### Scenario: Default execution returns records
- **WHEN** the user runs `edr web-application-scan` without optional filters
- **THEN** the system executes web application metadata collection and returns structured records

### Requirement: Collection MUST avoid external command execution
The system MUST collect web application information through in-process OS APIs, file/config parsing, or equivalent internal data access, and MUST NOT invoke external command-line tools during collection.

#### Scenario: Cross-platform non-command collection
- **WHEN** collection runs on Windows or Linux
- **THEN** no child process is launched for application enumeration commands

### Requirement: Query filters SHALL support requested parameters
The system SHALL support these optional request filters: `groups` (integer array), `hostname` (fuzzy), `ip` (fuzzy), `version` (string array), `appName`, `rootPath`, `webRoot`, `serverName` (string array), and `domainName`.

#### Scenario: Fuzzy host filters are applied
- **WHEN** the user provides `hostname` or `ip`
- **THEN** the system returns only records that match fuzzy rules for those fields

#### Scenario: Structured filters are combined
- **WHEN** the user provides any of `groups`, `version`, `appName`, `rootPath`, `webRoot`, `serverName`, or `domainName`
- **THEN** the system returns only records satisfying all provided filter conditions

### Requirement: Output schema SHALL expose normalized host and web-app fields
The system SHALL output records containing stable keys: `displayIp`, `externalIpList`, `internalIpList`, `bizGroupId`, `bizGroup`, `remark`, `hostTagList`, `hostname`, `version`, `webRoot`, `serverName`, `domainName`, `pluginCount`, `appName`, `description`, `rootPath`, and `plugins`.

#### Scenario: Contract keys are stable
- **WHEN** any web application record is returned
- **THEN** all contract keys are present with null or empty-array fallback when data is unavailable

### Requirement: Plugin objects MUST follow normalized sub-schema
The system MUST represent `plugins` as a list of objects, where each object includes `pluginName`, `pluginUri`, `description`, `author`, `authorUri`, and `version`.

#### Scenario: Plugin list is normalized
- **WHEN** plugin metadata exists for an application
- **THEN** each plugin entry is emitted using the normalized plugin sub-schema

### Requirement: Internal and external IP data MUST be list-based
The system MUST collect and output all available internal and external IP addresses as arrays, while preserving `displayIp` as a single display field.

#### Scenario: Multi-interface host IP mapping
- **WHEN** a host has multiple internal or external IP addresses
- **THEN** the output includes full values in `internalIpList` and `externalIpList`

### Requirement: Command SHALL support JSON and Excel outputs
The system SHALL support JSON output and Excel output for web application scan results.

#### Scenario: JSON output path
- **WHEN** the user selects JSON output or uses default output
- **THEN** the system emits JSON records conforming to the output schema

#### Scenario: Excel output path
- **WHEN** the user selects Excel output
- **THEN** the system generates an Excel file containing contract columns for web application records

### Requirement: Capability scope MUST remain information collection only
The system MUST limit this capability to collection and normalization of web application metadata and MUST NOT include risk scoring, alert severity, or threat conclusions.

#### Scenario: No risk-analysis fields in results
- **WHEN** web application scan completes
- **THEN** the output contains asset metadata only and excludes risk verdict fields
