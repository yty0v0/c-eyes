## ADDED Requirements

### Requirement: Hostscan help SHALL present parameter-oriented guidance
`edr hostscan -h` SHALL present concise parameter-oriented guidance and SHALL NOT use a “规则” section label in help output.

#### Scenario: Hostscan help removes rule-style section
- **WHEN** the user executes `edr hostscan -h`
- **THEN** the output uses operation/parameter descriptions and does not contain a “规则:” section

### Requirement: Hostscan risk help SHALL only show risk-usable modules and parameters
When risk mode is enabled for hostscan help, the output SHALL only list modules and risk parameters that are valid in hostscan chained risk analysis.

#### Scenario: Hostscan risk help hides non-risk modules
- **WHEN** the user executes `edr hostscan -r -h`
- **THEN** the module list only includes `process,startup,scheduledtask,kernel,database,application` and does not include host-info-only modules

#### Scenario: Process memory option is shown only when process module is usable
- **WHEN** hostscan risk help is generated for a module set that includes `process`
- **THEN** `-process-memory` is displayed as an available risk parameter

