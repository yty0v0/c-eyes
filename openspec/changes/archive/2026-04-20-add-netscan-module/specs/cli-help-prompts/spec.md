## MODIFIED Requirements

### Requirement: Root help SHALL follow fixed operation-oriented template
When users run `c-eyes -h` or `c-eyes --help`, the system SHALL output an English structured template with `NAME`, `USAGE`, `DESCRIPTION`, `COMMANDS`, and `GLOBAL OPTIONS` sections.

#### Scenario: Root help uses sectioned command reference
- **WHEN** the user executes `c-eyes -h`
- **THEN** the output contains the section headers `NAME`, `USAGE`, `DESCRIPTION`, `COMMANDS`, and `GLOBAL OPTIONS`
- **AND** `COMMANDS` includes `hostscan`, `filescan`, `eventlog`, and `netscan`

## ADDED Requirements

### Requirement: Netscan help SHALL separate execute and filter parameters
The system SHALL display `netscan` module help with clear section separation for request execution parameters and request filter parameters.

#### Scenario: Netscan help exposes execute and filter sections
- **WHEN** the user executes `c-eyes netscan -h`
- **THEN** help output includes `NAME`, `USAGE`, `EXECUTE OPTIONS`, and `FILTER OPTIONS`
- **AND** `EXECUTE OPTIONS` documents target/mode/runtime control parameters
- **AND** `FILTER OPTIONS` documents post-collection filtering and sorting parameters

### Requirement: Netscan help SHALL document collection-only and permission behavior in English
The system SHALL document in `netscan` help that the module is collection-only, does not support risk-analysis flags, and may require elevated privileges for specific probe modes.

#### Scenario: Netscan help declares risk-analysis unsupported
- **WHEN** the user executes `c-eyes netscan -h`
- **THEN** help explicitly states that `-r/--riskanalyze` is not supported for `netscan`

#### Scenario: Netscan help declares privilege requirements
- **WHEN** the user executes `c-eyes netscan -h`
- **THEN** help includes English notes that certain modes may require elevated privileges
- **AND** users are informed that permission failures return explicit English error messages

### Requirement: Netscan help SHALL list probe mode legend and default mode
The system SHALL list all nine probe mode abbreviations with full-name expansion in `netscan` help and SHALL declare the default mode value.

#### Scenario: Netscan help shows mode legend and default A
- **WHEN** the user executes `c-eyes netscan -h`
- **THEN** `-scanMode` help text lists `A, ICP, ICA, ICT, T, TS, U, N, O` with full-name expansion
- **AND** the help text explicitly declares default mode as `A`
