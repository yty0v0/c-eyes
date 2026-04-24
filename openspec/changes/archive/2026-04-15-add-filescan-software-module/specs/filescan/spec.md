## MODIFIED Requirements

### Requirement: Filescan help SHALL be grouped by usable mode and parameters
`edr filescan -h` SHALL present English option-oriented help with `NAME`, `USAGE`, and `OPTIONS`.  
The options SHALL include Web module selection (`--custom site/framework/jarpackage/software`, `--all`) and local scan-mode usage (`--scan-mode full/path/smart`) with explicit mutual-exclusion guidance among `--custom`, `--all`, and `--scan-mode`.

#### Scenario: Filescan base help shows web and local mode options in English
- **WHEN** the user executes `edr filescan -h`
- **THEN** the output is shown in English with `NAME`, `USAGE`, and `OPTIONS`
- **AND** the `OPTIONS` section documents `--custom` Web modules including `software`, `--all`, and `--scan-mode` local mode usage
- **AND** those option descriptions explicitly state mutual-exclusion relationships among `--custom`, `--all`, and `--scan-mode`

### Requirement: Filescan custom module help SHALL support single and multi-module inspection
For `edr filescan --custom <modules> -h`, the help output SHALL be module-scoped and MUST present only the relevant `OPTIONS` section for the selected module set, including `software`.

#### Scenario: Single custom software module help shows only software options
- **WHEN** the user executes `edr filescan --custom software -h`
- **THEN** the help output shows only the `OPTIONS` section for `software` module filtering parameters

#### Scenario: Multi custom module help with software shows intersection options
- **WHEN** the user executes `edr filescan --custom site,software -h`
- **THEN** the help output shows only the `OPTIONS` section for the selected modules' common parameter intersection

## ADDED Requirements

### Requirement: Filescan web-module routing SHALL execute software module paths
For non-local filescan execution, the system SHALL recognize `software` as a valid web-mode module in `--custom` and `--all` routes.

#### Scenario: Filescan custom software dispatch
- **WHEN** the user executes `edr filescan --custom software`
- **THEN** the command dispatches only the software collector path and returns software rows in unified scan output

#### Scenario: Filescan all-mode includes software dispatch
- **WHEN** the user executes `edr filescan --all`
- **THEN** the command dispatches `software` together with all other filescan web modules and returns merged deduplicated rows

### Requirement: Filescan local mode SHALL remain mutually exclusive with software web-mode
The system MUST keep `--scan-mode` mutually exclusive with all web modules, including `software`.

#### Scenario: Local mode mixed with software module is rejected
- **WHEN** the user executes `edr filescan --custom software --scan-mode smart`
- **THEN** the command returns an argument conflict error indicating local scan mode cannot be used with web-module selection

### Requirement: Filescan chained risk mapping SHALL include software path candidates
When `filescan -r` runs with software rows, the system SHALL map software records to risk scan records using file target candidates from `binPath` and `configPath`.

#### Scenario: Software row creates risk records from bin and config paths
- **WHEN** a software row contains `binPath` and/or `configPath` during `edr filescan --custom software -r`
- **THEN** the chained risk input includes candidate `target_path` values derived from those fields with deduplicated paths

#### Scenario: Filescan risk output behavior remains risk-only for software runs
- **WHEN** the user executes `edr filescan --custom software -r`
- **THEN** the command outputs risk-analysis results only and does not emit raw software scan rows

### Requirement: Filescan multi-module intersection SHALL remain stable when software participates
In multi-module web-mode runs that include `software`, the system SHALL keep intersection-only argument behavior (`groups`, `hostname`, `ip`) for shared filtering.

#### Scenario: Non-intersection argument is rejected in software multi-module mode
- **WHEN** the user executes `edr filescan --custom site,software -name nginx`
- **THEN** the command returns an argument error indicating multi-module mode only supports intersection filters
