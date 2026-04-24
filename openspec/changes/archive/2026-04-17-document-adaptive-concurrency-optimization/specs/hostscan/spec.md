## ADDED Requirements

### Requirement: Hostscan unified execution SHALL use adaptive module concurrency
For multi-module host scans, the system SHALL schedule module execution with bounded adaptive concurrency instead of a fixed single-worker plan.

#### Scenario: Hostscan all-mode runs modules concurrently within bounds
- **WHEN** the user executes `c-eyes hostscan --all`
- **THEN** the runtime schedules module tasks concurrently with an active worker count between configured minimum and maximum bounds
- **AND** active workers never exceed the selected module count

#### Scenario: Hostscan adaptive scheduler scales down under pressure
- **WHEN** hostscan adaptive scheduler detects high CPU utilization or high runtime memory pressure
- **THEN** active module concurrency is reduced stepwise down to the configured minimum bound

#### Scenario: Hostscan adaptive scheduler scales up when backlog is high
- **WHEN** hostscan still has substantial module backlog and runtime pressure is low
- **THEN** active module concurrency is increased stepwise up to the configured maximum bound
