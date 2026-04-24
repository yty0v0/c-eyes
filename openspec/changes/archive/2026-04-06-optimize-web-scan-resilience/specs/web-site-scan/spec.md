## ADDED Requirements

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

### Requirement: Output SHALL include runtime active-state marker
The system SHALL provide `isRunning` in web-site output to indicate whether runtime process association matched.

#### Scenario: Runtime association sets active flag
- **WHEN** a site record is enriched from matched process metadata
- **THEN** `isRunning` is true; otherwise false

