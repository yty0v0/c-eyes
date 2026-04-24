## ADDED Requirements

### Requirement: Project hash baseline whitelist SHALL be enabled by default
Risk whitelist setup MUST attempt project hash baseline integration by default when running inside a detectable project root.

#### Scenario: Default run inside project root auto-integrates baseline
- **WHEN** whitelist setup runs with `C_EYES_ENABLE_PROJECT_WHITELIST` unset and project root is detected
- **THEN** baseline hash file is created or loaded automatically
- **AND** baseline path is appended to enterprise hash repositories once (deduplicated)

#### Scenario: Default run without detectable project root is no-op
- **WHEN** whitelist setup runs with `C_EYES_ENABLE_PROJECT_WHITELIST` unset and project root cannot be detected
- **THEN** setup does not fail hard
- **AND** no project baseline repository is added

### Requirement: Project whitelist environment switches MUST support explicit override
Whitelist bootstrap MUST support explicit enable/disable and path overrides through environment variables.

#### Scenario: Explicit disable bypasses project baseline setup
- **WHEN** `C_EYES_ENABLE_PROJECT_WHITELIST=0`
- **THEN** project baseline setup is skipped
- **AND** no baseline file is created by that path

#### Scenario: Explicit enable with undetectable root reports setup failure
- **WHEN** `C_EYES_ENABLE_PROJECT_WHITELIST=1` and no project root can be detected
- **THEN** setup returns an explicit failure
- **AND** caller prints a warning line instead of success noise

### Requirement: Project baseline generator SHALL include executable identity artifacts
Project baseline generation MUST include core project source/rules scope and executable identity artifacts needed to prevent self-detection drift.

#### Scenario: Baseline include rules cover c-eyes executable names
- **WHEN** baseline hashes are generated for project scope
- **THEN** include rules accept `c-eyes` and `c-eyes.exe` artifacts when present
- **AND** resulting hash list remains deduplicated
