## MODIFIED Requirements

### Requirement: Collection MUST avoid external command execution
The system MUST collect web application information through in-process APIs, configuration parsing, and process metadata correlation; and MUST parse include-linked configuration fragments without invoking external command-line tools.

#### Scenario: Include-based config is fully considered
- **WHEN** a main config references child configs via include directives
- **THEN** the collector recursively resolves include targets (within depth limits) and applies merged content to normalized output

### Requirement: Output schema SHALL expose normalized host and web-app fields
The system SHALL keep stable output keys and SHALL include runtime state indicator `isRunning`.

#### Scenario: Runtime association marks active assets
- **WHEN** an application record is enriched by matched running process metadata
- **THEN** the output sets `isRunning=true`; otherwise defaults to `false`

