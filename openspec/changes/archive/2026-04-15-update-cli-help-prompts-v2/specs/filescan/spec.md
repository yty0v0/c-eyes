## MODIFIED Requirements

### Requirement: Filescan help SHALL be grouped by usable mode and parameters
`edr filescan -h` SHALL present English option-oriented help with `NAME`, `USAGE`, and `OPTIONS`.  
The options SHALL include Web module selection (`--custom site/framework/jarpackage`, `--all`) and local scan-mode usage (`--scan-mode full/path/smart`) with explicit mutual-exclusion guidance among `--custom`, `--all`, and `--scan-mode`.

#### Scenario: Filescan base help shows web and local mode options in English
- **WHEN** the user executes `edr filescan -h`
- **THEN** the output is shown in English with `NAME`, `USAGE`, and `OPTIONS`
- **AND** the `OPTIONS` section documents `--custom` Web modules, `--all`, and `--scan-mode` local mode usage
- **AND** those option descriptions explicitly state mutual-exclusion relationships among `--custom`, `--all`, and `--scan-mode`

### Requirement: Filescan risk help SHALL include risk-usable parameter categories
Filescan help SHALL consolidate risk-parameter guidance into `edr filescan -h`, and `edr filescan -r -h` SHALL no longer require a separate dedicated risk-help page.

#### Scenario: Risk parameters are visible in filescan help page
- **WHEN** the user executes `edr filescan -h`
- **THEN** the output includes an `OPTIONS(only -r enable can use)` section
- **AND** that section includes `-yara-rules`, `-analysis-max-duration`, `-cloud-upload`, and `--risk-mode`

#### Scenario: Filescan risk-help entry reuses consolidated page
- **WHEN** the user executes `edr filescan -r -h`
- **THEN** the command shows the consolidated filescan help content instead of a separate risk-only help page

## ADDED Requirements

### Requirement: Filescan custom module help SHALL support single and multi-module inspection
For `edr filescan --custom <modules> -h`, the help output SHALL be module-scoped and MUST present only the relevant `OPTIONS` section for the selected module set.

#### Scenario: Single custom module help shows only that module options
- **WHEN** the user executes `edr filescan --custom site -h`
- **THEN** the help output shows only the `OPTIONS` section for `site` module filtering parameters

#### Scenario: Multi custom module help shows intersection options
- **WHEN** the user executes `edr filescan --custom site,framework -h`
- **THEN** the help output shows only the `OPTIONS` section for the selected modules' common parameter intersection

### Requirement: Filescan runtime SHALL require explicit execution mode
For non-help execution, unified filescan SHALL require one of `--all`, `--custom`, or `--scan-mode`.

#### Scenario: Filescan rejects missing execution mode flags
- **WHEN** the user executes `edr filescan` without `--all`, `--custom`, and `--scan-mode`
- **THEN** the command returns an argument error indicating filescan requires one of `--all`, `--custom`, or `--scan-mode`

### Requirement: Filescan unified execution SHALL display terminal progress
During unified filescan execution (Web module mode and local scan-mode), progress rows SHALL be shown in terminal output.

#### Scenario: Filescan local path scan prints progress rows
- **WHEN** the user executes `edr filescan --scan-mode path <path>`
- **THEN** stderr includes progress rows labeled `filescan` with `done/total` counters
- **AND** progress stage includes local-mode scope such as `scan-mode=path | <stage>`
