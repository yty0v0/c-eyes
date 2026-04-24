## MODIFIED Requirements

### Requirement: Hostscan help SHALL present parameter-oriented guidance
`edr hostscan -h` SHALL present English option-oriented help with `NAME`, `USAGE`, and `OPTIONS` sections.  
The options section SHALL document module selection via `--custom` and `--all` with explicit mutual-exclusion guidance, and SHALL include both information-scan supported modules and risk-analysis supported modules.

#### Scenario: Hostscan base help is English and option-oriented
- **WHEN** the user executes `edr hostscan -h`
- **THEN** the output is shown in English with `NAME`, `USAGE`, and `OPTIONS`
- **AND** the `--custom` option documents information-scan modules `account,usergroup,process,port,startup,scheduledtask,environment,kernel,database,application`
- **AND** the same section documents risk-analysis modules `process,startup,scheduledtask,kernel,database,application`
- **AND** the help output includes `--all` and states that `--all` and `--custom` are mutually exclusive

### Requirement: Hostscan risk help SHALL only show risk-usable modules and parameters
Hostscan help SHALL consolidate risk-parameter guidance into `edr hostscan -h`, and `edr hostscan -r -h` SHALL no longer require a separate dedicated risk-help page.

#### Scenario: Risk parameters are visible in hostscan help page
- **WHEN** the user executes `edr hostscan -h`
- **THEN** the output includes an `OPTIONS(only -r enable can use)` section
- **AND** that section includes `-yara-rules`, `-analysis-max-duration`, and `-process-memory`

#### Scenario: Hostscan risk-help entry reuses consolidated page
- **WHEN** the user executes `edr hostscan -r -h`
- **THEN** the command shows the consolidated hostscan help content instead of a separate risk-only help page

## ADDED Requirements

### Requirement: Hostscan custom module help SHALL support single and multi-module inspection
For `edr hostscan --custom <modules> -h`, the help output SHALL be module-scoped and MUST present only the relevant `OPTIONS` section for the selected module set.

#### Scenario: Single custom module help shows only that module options
- **WHEN** the user executes `edr hostscan --custom account -h`
- **THEN** the help output shows only the `OPTIONS` section for `account` module filtering parameters

#### Scenario: Multi custom module help shows intersection options
- **WHEN** the user executes `edr hostscan --custom account,usergroup -h`
- **THEN** the help output shows only the `OPTIONS` section for the selected modules' common parameter intersection

### Requirement: Hostscan runtime SHALL require explicit module-selection mode
For non-help execution, unified hostscan SHALL require explicit module-selection mode via `--all` or `--custom`.

#### Scenario: Hostscan rejects implicit default module selection
- **WHEN** the user executes `edr hostscan` without `--all` and without `--custom`
- **THEN** the command returns an argument error indicating hostscan requires `--all` or `--custom`

### Requirement: Hostscan unified execution SHALL display terminal progress
During unified hostscan execution, progress rows SHALL be shown in terminal output and scoped by selected module stage.

#### Scenario: Hostscan custom module scan prints scoped progress rows
- **WHEN** the user executes `edr hostscan --custom account`
- **THEN** stderr includes progress rows labeled `hostscan` with `done/total` counters
- **AND** the progress stage includes module context such as `account | <stage>`
