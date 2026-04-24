## ADDED Requirements

### Requirement: Filescan local path mode SHALL return explicit access-denied root errors
For `--scan-mode path <path>`, if the declared root path cannot be enumerated due to permissions, filescan MUST fail with a clear access-denied path error.

#### Scenario: Path root access denied
- **WHEN** a user executes `c-eyes filescan --scan-mode path <path>` and `<path>` is not listable by current user
- **THEN** filescan exits with a path-scoped access-denied error
- **AND** the message references the denied scan path

### Requirement: Filescan local collection SHALL report inaccessible entries and continue
During local collection in `full` or `path` scope, walker-level permission failures MUST be reported per inaccessible entry and MUST NOT abort the whole run.

#### Scenario: Multiple denied entries in one scan scope
- **WHEN** collection traverses a scope that contains multiple inaccessible files/directories
- **THEN** filescan prints one warning per denied entry encountered by the collector
- **AND** scanning continues for remaining accessible targets

#### Scenario: Denied directory does not produce synthetic child warnings
- **WHEN** a directory entry itself is inaccessible to traversal
- **THEN** filescan reports that denied entry
- **AND** filescan does not emit fabricated warnings for unknown descendants under that denied directory

### Requirement: Filescan chained risk SHALL keep phase-separated progress behavior
In `filescan -r` mode, filescan phase and risk phase progress MUST remain phase-separated and readable.

#### Scenario: Filescan and risk progress rows remain sequentially readable
- **WHEN** a user executes `c-eyes filescan ... -r`
- **THEN** filescan progress completes first
- **AND** risk progress runs as a single active row during risk phase without spawning parallel duplicate rows
