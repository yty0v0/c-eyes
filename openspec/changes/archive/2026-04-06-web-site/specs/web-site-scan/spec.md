## ADDED Requirements

### Requirement: CLI MUST provide web site collection command
The system SHALL provide an `edr web-site-scan` command to collect web site metadata from Windows and Linux endpoints and return normalized records.

#### Scenario: Default execution returns records
- **WHEN** the user runs `edr web-site-scan` without optional filters
- **THEN** the system executes web site metadata collection and returns structured results

### Requirement: Collection MUST avoid external command execution
The system MUST collect web site information through in-process OS APIs, configuration parsing, or equivalent internal access, and MUST NOT invoke external command-line tools during collection.

#### Scenario: Cross-platform non-command collection
- **WHEN** collection runs on Windows or Linux
- **THEN** no child process is launched for web site enumeration commands

### Requirement: Query filters SHALL support requested parameters
The system SHALL support these optional request filters: `groups` (integer array), `hostname` (fuzzy), `ip` (fuzzy), `port` (integer), `proto` (exact), `type` (string array exact), and `rootPath` (fuzzy).

#### Scenario: Host fuzzy filters are applied
- **WHEN** the user provides `hostname` or `ip`
- **THEN** the system returns only records matching fuzzy rules for those fields

#### Scenario: Structured filters are combined
- **WHEN** the user provides any of `groups`, `port`, `proto`, `type`, or `rootPath`
- **THEN** the system returns only records satisfying all provided filter conditions

### Requirement: Output schema SHALL expose normalized web site fields
The system SHALL output records with stable keys including `displayIp`, `externalIpList`, `internalIpList`, `bizGroupId`, `bizGroup`, `remark`, `hostTagList`, `hostname`, `pid`, `allow`, `deny`, `cmd`, `domains`, `user`, `type`, `port`, `proto`, `portStatus`, `securityEnabled`, `virtualDir`, `root`, `virtualDirCount`, `bindingCount`, `deployPath`, `configName`, `state`, and `path`.

#### Scenario: Contract keys are stable
- **WHEN** any web site record is returned
- **THEN** all contract keys are present with null or empty-array fallback when data is unavailable

### Requirement: Domain binding list MUST use normalized object schema
The system MUST represent `domains` as a list of objects with keys `name`, `title`, and `ip`.

#### Scenario: Domain list normalization
- **WHEN** domain binding metadata exists
- **THEN** each domain binding is emitted using the normalized schema

### Requirement: Virtual directory and root objects MUST be normalized
The system MUST represent `virtualDir` as a list of structured directory objects and `root` as a structured primary-directory object, supporting platform-specific fields such as Linux permission metadata and Windows ACL/appPool metadata.

#### Scenario: Mixed platform directory metadata
- **WHEN** virtual directory metadata is collected from different platforms
- **THEN** the output preserves shared fields and emits platform-specific fields only where applicable

### Requirement: Internal and external IP data MUST be list-based
The system MUST collect all available internal and external IP addresses as arrays and expose them via `internalIpList` and `externalIpList`; single-value storage fields for internal/external IP MUST NOT be required by this capability.

#### Scenario: Multi-interface host IP mapping
- **WHEN** a host has multiple internal or external IP addresses
- **THEN** the output includes full values in `internalIpList` and `externalIpList`

### Requirement: Command SHALL support JSON and Excel outputs
The system SHALL support JSON output and Excel output for web site scan results.

#### Scenario: JSON output path
- **WHEN** the user selects JSON output or uses default output
- **THEN** the system emits JSON records conforming to the output schema

#### Scenario: Excel output path
- **WHEN** the user selects Excel output
- **THEN** the system generates an Excel file containing contract columns for web site records

### Requirement: Capability scope MUST remain information collection only
The system MUST limit this capability to collection and normalization of web site metadata and MUST NOT include risk scoring, threat verdicts, or remediation conclusions.

#### Scenario: No risk-analysis fields in results
- **WHEN** web site scan completes
- **THEN** the output contains asset metadata only and excludes risk-analysis results

### Requirement: CLI messaging and file encoding MUST satisfy localization constraints
The system MUST use Chinese prompt messages for CLI interaction and MUST encode output text content in UTF-8.

#### Scenario: Chinese prompt and UTF-8 output
- **WHEN** the user executes web site scan and exports results
- **THEN** command prompts are in Chinese and generated text content uses UTF-8 encoding
