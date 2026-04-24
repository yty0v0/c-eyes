## ADDED Requirements

### Requirement: Filescan web-module execution SHALL use adaptive module concurrency
For multi-module web-mode filescan execution, the system SHALL run module collectors with bounded adaptive concurrency using runtime pressure and backlog signals.

#### Scenario: Filescan all web modules execute with bounded adaptive concurrency
- **WHEN** the user executes `c-eyes filescan --all`
- **THEN** module collectors run concurrently with active workers between configured minimum and maximum bounds
- **AND** active workers never exceed selected web-module count

#### Scenario: Filescan web adaptive scheduler reacts to pressure and backlog
- **WHEN** runtime CPU/memory pressure is high during web-mode module execution
- **THEN** active module concurrency is reduced toward minimum bound
- **AND** when pressure is low with remaining backlog, active module concurrency is increased toward maximum bound

### Requirement: Filescan local mode SHALL reject manual workers flag
Local filescan runtime concurrency MUST be managed automatically, and manual `--workers` input SHALL be rejected.

#### Scenario: Local filescan rejects --workers flag
- **WHEN** the user executes `c-eyes filescan --scan-mode path <path> --workers 4`
- **THEN** the command returns an argument error indicating `--workers` is not supported

#### Scenario: Local filescan keeps automatic concurrency when workers flag is absent
- **WHEN** the user executes `c-eyes filescan --scan-mode smart` without `--workers`
- **THEN** local scan starts with runtime-selected adaptive concurrency behavior
