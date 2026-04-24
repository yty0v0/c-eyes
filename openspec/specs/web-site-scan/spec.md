# web-site-scan Specification

## Purpose
Collect and normalize web site metadata across Windows and Linux endpoints for inventory and export workflows.

## Requirements
### Requirement: CLI MUST provide web site collection command
The system SHALL provide an `c-eyes web-site-scan` command to collect web site metadata from Windows and Linux endpoints and return normalized records.

#### Scenario: Default execution returns records
- **WHEN** the user runs `c-eyes web-site-scan` without optional filters
- **THEN** the system executes web site metadata collection and returns structured results

### Requirement: Collection MUST avoid external command execution
The system MUST collect web site information through in-process OS APIs, configuration parsing, and runtime process metadata correlation, and MUST NOT invoke external command-line tools during collection.

#### Scenario: Cross-platform non-command collection
- **WHEN** collection runs on Windows or Linux
- **THEN** no child process is launched for web site enumeration commands

### Requirement: Runtime process correlation SHALL enrich web site rows
The system SHALL correlate running web service processes with collected web site records to enrich runtime metadata including `pid`, `cmd`, and `user`.

#### Scenario: Existing static row is enriched by process metadata
- **WHEN** a static web site record matches a detected running process of the same service type
- **THEN** the output row includes runtime fields from process metadata without changing existing schema keys

### Requirement: Collector SHALL discover non-default config paths from process arguments
The system SHALL parse startup arguments of detected web service processes to discover non-default config file paths and, when readable, reuse existing config parsers to produce normalized site rows.

#### Scenario: Config path inferred from process command line
- **WHEN** a process provides config path via flags such as `-c`, `-f`, or explicit config file token
- **THEN** the collector resolves the path, parses the config in-process, and merges or appends normalized records

### Requirement: Config path normalization MUST resolve symlink targets
The system MUST normalize discovered config paths by resolving symlinks when possible before deduplication and merge.

#### Scenario: Symlinked config path deduplicates correctly
- **WHEN** a process argument references a symlinked config file
- **THEN** the collector resolves to real path and avoids duplicate site records for equivalent configs

### Requirement: Include directives SHALL be parsed with bounded recursion
The system SHALL parse include directives in supported web config formats using bounded recursion and visited tracking.

#### Scenario: Include chain contributes to final site metadata
- **WHEN** server name or listen directives exist only in included files
- **THEN** merged parsing output still contains normalized domain/port/protocol fields

### Requirement: Query filters SHALL support requested parameters
The system SHALL support these optional request filters: `groups` (integer array), `hostname` (fuzzy), `ip` (fuzzy), `port` (integer), `proto` (exact), `type` (string array exact), and `rootPath` (fuzzy).

#### Scenario: Host fuzzy filters are applied
- **WHEN** the user provides `hostname` or `ip`
- **THEN** the system returns only records matching fuzzy rules for those fields

#### Scenario: Structured filters are combined
- **WHEN** the user provides any of `groups`, `port`, `proto`, `type`, or `rootPath`
- **THEN** the system returns only records satisfying all provided filter conditions

### Requirement: Output schema SHALL expose normalized web site fields
The system SHALL output records with stable keys including `displayIp`, `externalIpList`, `internalIpList`, `bizGroupId`, `bizGroup`, `remark`, `hostTagList`, `hostname`, `pid`, `allow`, `deny`, `cmd`, `domains`, `user`, `type`, `port`, `proto`, `portStatus`, `securityEnabled`, `virtualDir`, `root`, `virtualDirCount`, `bindingCount`, `deployPath`, `configName`, `state`, `path`, and `isRunning`.

#### Scenario: Contract keys are stable
- **WHEN** any web site record is returned
- **THEN** all contract keys are present with null or empty-array fallback when data is unavailable

#### Scenario: Runtime association sets active flag
- **WHEN** a site record is enriched from matched process metadata
- **THEN** `isRunning` is true; otherwise false

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

#### Scenario: Dynamic enrichment output excludes risk fields
- **WHEN** runtime association is enabled
- **THEN** returned rows still exclude risk-analysis fields and remain compatible with existing JSON/Excel contracts

### Requirement: CLI messaging and file encoding MUST satisfy localization constraints
The system MUST use Chinese prompt messages for CLI interaction and MUST encode output text content in UTF-8.

#### Scenario: Chinese prompt and UTF-8 output
- **WHEN** the user executes web site scan and exports results
- **THEN** command prompts are in Chinese and generated text content uses UTF-8 encoding
