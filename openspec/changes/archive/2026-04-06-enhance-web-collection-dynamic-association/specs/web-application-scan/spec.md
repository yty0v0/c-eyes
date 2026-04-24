## MODIFIED Requirements

### Requirement: Collection MUST avoid external command execution
The system MUST collect web application information through in-process OS APIs, file/config parsing, and runtime process metadata correlation, and MUST NOT invoke external command-line tools during collection.

#### Scenario: Static-plus-dynamic collection without child process commands
- **WHEN** web application collection executes on Windows or Linux
- **THEN** the collector reads configuration files, host/process metadata, and performs in-process correlation without launching external enumeration commands

### Requirement: Output schema SHALL expose normalized host and web-app fields
The system SHALL continue to output stable keys and SHALL enrich missing values using runtime process association when static configuration paths are insufficient.

#### Scenario: Non-default config path is discovered from process arguments
- **WHEN** a web server runs with a non-default config path passed in startup arguments
- **THEN** the collector infers capability type and config path from process metadata and enriches application records with normalized fields

