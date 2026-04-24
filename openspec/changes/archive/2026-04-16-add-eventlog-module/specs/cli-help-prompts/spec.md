## MODIFIED Requirements

### Requirement: Root help SHALL follow fixed operation-oriented template
When users run `c-eyes -h` or `c-eyes --help`, the system SHALL output an English structured template with `NAME`, `USAGE`, `DESCRIPTION`, `COMMANDS`, and `GLOBAL OPTIONS` sections.

#### Scenario: Root help uses sectioned command reference
- **WHEN** the user executes `c-eyes -h`
- **THEN** the output contains the section headers `NAME`, `USAGE`, `DESCRIPTION`, `COMMANDS`, and `GLOBAL OPTIONS`
- **AND** `COMMANDS` includes `hostscan`, `filescan`, and `eventlog`
