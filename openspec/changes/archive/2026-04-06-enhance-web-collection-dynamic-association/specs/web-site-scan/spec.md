## ADDED Requirements

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

### Requirement: Dynamic enhancement MUST preserve information-only boundary
The system MUST keep this capability within information collection scope and MUST NOT add risk verdict or scoring fields during dynamic enrichment.

#### Scenario: Dynamic enrichment output excludes risk fields
- **WHEN** runtime association is enabled
- **THEN** returned rows still exclude risk-analysis fields and remain compatible with existing JSON/Excel contracts

