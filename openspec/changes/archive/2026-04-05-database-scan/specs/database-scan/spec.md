## ADDED Requirements

### Requirement: Cross-platform Database Information Collection
The system SHALL collect database metadata on both Windows and Linux hosts using a unified data model without invoking external command-line tools for collection.

#### Scenario: Collection on supported operating systems
- **WHEN** the operator runs database scan on Windows or Linux
- **THEN** the system returns database records in the same logical schema
- **AND** collection logic does not execute external shell/database client commands

### Requirement: Request Parameter Filtering
The system SHALL support optional request filters: `groups`, `hostname`, `ip`, `name`, `versions`, `port`, `confPath`, `logPath`, and `dataDir`.

#### Scenario: Fuzzy and exact filter behavior
- **WHEN** the operator provides `hostname`, `ip`, `confPath`, `logPath`, or `dataDir`
- **THEN** the system applies fuzzy matching to corresponding fields
- **AND** exact/contains matching is applied to numeric and array filters (`groups`, `versions`, `port`) according to field type

### Requirement: Standardized Output Fields
The system SHALL output standardized common fields for each database record: host network identity, business grouping, host identity, database identity, runtime, and path metadata.

#### Scenario: Common field completeness
- **WHEN** a database record is generated
- **THEN** the record includes fields equivalent to `displayIp`, business group info, `hostname`, `name`, `version`, `port`, protocol/user/bind IP, and config/log/data paths

### Requirement: Platform and Database Specific Fields
The system SHALL include conditional fields for specific platforms or database types, including but not limited to `pluginDir`, `rest`, `auth`, `web`, `webPort`, `webAddress`, `regionServer`, `dbName`, `loginModel`, `auditLevel`, `sysLogPath`, and `mainDbPath`.

#### Scenario: Conditional field emission
- **WHEN** a record belongs to Linux MySQL, Linux MongoDB, Linux HBase, Oracle, or Windows SQL Server
- **THEN** the system populates the applicable conditional fields
- **AND** non-applicable fields are omitted or left empty according to serialization policy

### Requirement: Multi-address IP Representation
The system SHALL represent internal and external IP addresses as arrays to preserve all discovered addresses for a host.

#### Scenario: Host with multiple NIC addresses
- **WHEN** a host has multiple internal or external IP addresses
- **THEN** the output includes all discovered addresses in array form
- **AND** no addresses are dropped due to single-value truncation

### Requirement: CLI Output Formats
The system SHALL provide a command-line interface to run database scan and export results in `json` and `excel` formats.

#### Scenario: JSON output
- **WHEN** the operator specifies JSON output (or default output)
- **THEN** the system writes scan results in valid JSON format

#### Scenario: Excel output
- **WHEN** the operator specifies Excel output
- **THEN** the system writes scan results into an Excel file with stable column mapping from the standardized schema

### Requirement: Information Collection Only
The system SHALL restrict the database-scan module to information collection and MUST NOT generate risk analysis conclusions.

#### Scenario: Scan result scope
- **WHEN** database scan completes
- **THEN** the output contains only collected metadata
- **AND** no risk scoring, vulnerability judgment, or remediation recommendation is produced
