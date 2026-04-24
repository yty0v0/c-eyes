## ADDED Requirements

### Requirement: Filescan help SHALL be grouped by usable mode and parameters
`edr filescan -h` SHALL present Web-module usage and local scan-mode usage as clear parameter groups without rule-style narrative blocks.

#### Scenario: Filescan help shows web and local groups
- **WHEN** the user executes `edr filescan -h`
- **THEN** the output separately documents Web module usage (`--custom site/framework/jarpackage`) and local mode usage (`--scan-mode full/path/smart` plus `--max-targets`)

### Requirement: Filescan risk help SHALL include risk-usable parameter categories
When filescan help is shown with risk enabled, the output SHALL include risk-usable parameter categories for chained analysis.

#### Scenario: Filescan risk help shows risk categories
- **WHEN** the user executes `edr filescan -r -h`
- **THEN** the output includes `-yara-rules`, `-analysis-max-duration`, `--risk-mode`, and `-cloud-upload` as available risk analysis parameters

