## ADDED Requirements

### Requirement: Root help SHALL include benchmark command entry
Root help output SHALL list `benchmark` as a first-class command in the `COMMANDS` section.

#### Scenario: Root help lists benchmark command
- **WHEN** the user executes `c-eyes -h`
- **THEN** the `COMMANDS` section includes `benchmark`
- **AND** the command description indicates baseline/security benchmark checking capability

### Requirement: Benchmark help SHALL use structured English command template
The system SHALL provide `c-eyes benchmark -h` help in English with structured sections consistent with unified modules.

#### Scenario: Benchmark subcommand help uses standard sections
- **WHEN** the user executes `c-eyes benchmark -h`
- **THEN** help output includes `NAME`, `USAGE`, and `OPTIONS`
- **AND** options include `--template auto|windows|linux|euleros|kylin`

### Requirement: Benchmark help SHALL declare collection-only and privilege behavior
Benchmark help SHALL explicitly document collection-only behavior and required privilege level.

#### Scenario: Benchmark help states no risk-analysis support
- **WHEN** the user executes `c-eyes benchmark -h`
- **THEN** help text states `benchmark` does not support `-r/--riskanalyze`

#### Scenario: Benchmark help states privilege requirement
- **WHEN** the user executes `c-eyes benchmark -h`
- **THEN** help text states Windows requires administrator privilege
- **AND** help text states Linux-family systems require root privilege
