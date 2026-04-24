# web-application-scan Specification

## Purpose
Collect and normalize web application metadata across Windows and Linux endpoints for inventory and export workflows.

## Requirements
### Requirement: CLI MUST provide web application collection command
The system SHALL provide an `c-eyes web-application-scan` command to collect web application metadata from Windows and Linux endpoints and return normalized results.

#### Scenario: Default execution returns records
- **WHEN** the user runs `c-eyes web-application-scan` without optional filters
- **THEN** the system executes web application metadata collection and returns structured records

### Requirement: Collection MUST avoid external command execution
The system MUST collect web application information through in-process OS APIs, configuration parsing (including include-linked configuration fragments), and runtime process metadata correlation, and MUST NOT invoke external command-line tools during collection.

#### Scenario: Cross-platform non-command collection
- **WHEN** collection runs on Windows or Linux
- **THEN** no child process is launched for application enumeration commands

#### Scenario: Static-plus-dynamic collection without child process commands
- **WHEN** web application collection executes on Windows or Linux
- **THEN** the collector reads configuration files and host/process metadata, and performs in-process correlation without launching external enumeration commands

#### Scenario: Include-based config is fully considered
- **WHEN** a main config references child configs via include directives
- **THEN** the collector recursively resolves include targets (within depth limits) and applies merged content to normalized output

### Requirement: Query filters SHALL support requested parameters
The system SHALL support these optional request filters: `groups` (integer array), `hostname` (fuzzy), `ip` (fuzzy), `version` (string array), `appName`, `rootPath`, `webRoot`, `serverName` (string array), and `domainName`.

#### Scenario: Fuzzy host filters are applied
- **WHEN** the user provides `hostname` or `ip`
- **THEN** the system returns only records that match fuzzy rules for those fields

#### Scenario: Structured filters are combined
- **WHEN** the user provides any of `groups`, `version`, `appName`, `rootPath`, `webRoot`, `serverName`, or `domainName`
- **THEN** the system returns only records satisfying all provided filter conditions

### Requirement: Output schema SHALL expose normalized host and web-app fields
The system SHALL output records containing stable keys: `displayIp`, `externalIpList`, `internalIpList`, `bizGroupId`, `bizGroup`, `remark`, `hostTagList`, `hostname`, `version`, `webRoot`, `serverName`, `domainName`, `pluginCount`, `appName`, `description`, `rootPath`, `plugins`, and `isRunning`. The system SHALL enrich missing values using runtime process association when static configuration paths are insufficient.

#### Scenario: Contract keys are stable
- **WHEN** any web application record is returned
- **THEN** all contract keys are present with null or empty-array fallback when data is unavailable

#### Scenario: Non-default config path is discovered from process arguments
- **WHEN** a web server runs with a non-default config path passed in startup arguments
- **THEN** the collector infers capability type and config path from process metadata and enriches application records with normalized fields

#### Scenario: Runtime association marks active assets
- **WHEN** an application record is enriched by matched running process metadata
- **THEN** the output sets `isRunning=true`; otherwise defaults to `false`

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
