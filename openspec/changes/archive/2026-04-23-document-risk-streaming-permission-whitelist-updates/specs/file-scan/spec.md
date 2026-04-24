## ADDED Requirements

### Requirement: Path-mode collection MUST pre-check directory readability
Before walking `ScanModePath` roots, local file collection MUST verify root readability for directory paths and MUST fail early on permission denial.

#### Scenario: Directory root fails readability probe
- **WHEN** local path scan targets a directory root that exists but is not readable
- **THEN** collection fails early with an access-denied error for that root
- **AND** the run does not silently downgrade to "no targets found"

#### Scenario: File root bypasses directory-read probe
- **WHEN** local path scan target is a single file path
- **THEN** collection does not require directory-read probing
- **AND** the file remains eligible for scanning

### Requirement: Collector walker MUST surface entry-level permission errors via task callback
The local collector walker MUST surface permission and metadata-read failures through task-scoped error callbacks so callers can print per-entry diagnostics.

#### Scenario: Walk callback emits two denied entry errors
- **WHEN** walker encounters two separate inaccessible entries in one traversal
- **THEN** callback is invoked twice with stage `collect_targets`
- **AND** each callback includes the denied entry path and associated error
