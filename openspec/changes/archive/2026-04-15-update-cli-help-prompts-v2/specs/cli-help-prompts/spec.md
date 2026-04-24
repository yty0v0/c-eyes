## MODIFIED Requirements

### Requirement: Root help SHALL follow fixed operation-oriented template
When users run `edr -h` or `edr --help`, the system SHALL output an English structured template with `NAME`, `USAGE`, `DESCRIPTION`, `COMMANDS`, and `GLOBAL OPTIONS` sections.

#### Scenario: Root help uses sectioned command reference
- **WHEN** the user executes `edr -h`
- **THEN** the output contains the section headers `NAME`, `USAGE`, `DESCRIPTION`, `COMMANDS`, and `GLOBAL OPTIONS`
- **AND** `COMMANDS` includes `hostscan` and `filescan`

### Requirement: Root help SHALL include risk source parameter details
Root help SHALL expose risk-analysis entry guidance through global options by documenting `-r, --riskanalyze` and directing users to `edr -r -h` for detailed source parameters.

#### Scenario: Root help references standalone risk help entry
- **WHEN** the user executes `edr --help`
- **THEN** `GLOBAL OPTIONS` includes `-r, --riskanalyze`
- **AND** the risk option description instructs users to check `edr -r -h` for detailed analysis-source usage

