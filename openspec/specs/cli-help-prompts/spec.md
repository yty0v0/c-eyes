# CLI Help Prompts

## Purpose

Define root and subcommand help output expectations for `c-eyes` so users can discover executable command paths quickly, with risk parameters documented in structured sections.
## Requirements
### Requirement: Root help SHALL follow fixed operation-oriented template
When users run `c-eyes -h` or `c-eyes --help`, the system SHALL output an English structured template with `NAME`, `USAGE`, `DESCRIPTION`, `COMMANDS`, and `GLOBAL OPTIONS` sections.

#### Scenario: Root help uses sectioned command reference
- **WHEN** the user executes `c-eyes -h`
- **THEN** the output contains the section headers `NAME`, `USAGE`, `DESCRIPTION`, `COMMANDS`, and `GLOBAL OPTIONS`
- **AND** `COMMANDS` includes `hostscan`, `filescan`, `eventlog`, and `netscan`

### Requirement: Root help SHALL include risk source parameter details
Root help SHALL expose risk-analysis entry guidance through global options by documenting `-r, --riskanalyze` and directing users to `c-eyes -r -h` for detailed source parameters.

#### Scenario: Root help references standalone risk help entry
- **WHEN** the user executes `c-eyes --help`
- **THEN** `GLOBAL OPTIONS` includes `-r, --riskanalyze`
- **AND** the risk option description instructs users to check `c-eyes -r -h` for detailed analysis-source usage

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

### Requirement: Netscan help SHALL document reachable-segment execute option behavior
The system SHALL document the `-reachableSegments` execute option in `netscan` help, including that it is opt-in and focused on routed reachable-segment discovery.

#### Scenario: Netscan help includes reachable-segment option in execute section
- **WHEN** the user executes `c-eyes netscan -h`
- **THEN** `EXECUTE OPTIONS` includes `-reachableSegments`
- **AND** the option description states that routed reachable-segment discovery is enabled only when this option is set

#### Scenario: Netscan help clarifies bounded behavior for reachable-segment mode
- **WHEN** the user executes `c-eyes netscan -h`
- **THEN** help text explains that reachable-segment discovery remains bounded by existing scan safety controls
- **AND** users are directed to use explicit targets when they need strict scan scope control

### Requirement: Root help SHALL include sbom command entry
When users run root help, the command listing SHALL include `sbom` as a first-class module command.

#### Scenario: Root help lists sbom command
- **WHEN** the user executes `c-eyes -h`
- **THEN** the `COMMANDS` section includes `sbom`
- **AND** `sbom` description indicates software bill-of-materials collection capability

### Requirement: SBOM help SHALL use English structured subcommand template
The system SHALL provide English help for `c-eyes sbom` with structured sections and option descriptions consistent with other unified modules.

#### Scenario: SBOM subcommand help uses standard sections
- **WHEN** the user executes `c-eyes sbom -h`
- **THEN** help output includes `NAME`, `USAGE`, and `OPTIONS`
- **AND** options include target selectors `-p/--path`, `--image-target`, optional `--target-type auto|image|archive|oci-layout`, and `--format` with values `xspdx-json|spdx-json`

#### Scenario: SBOM help states collection-only behavior
- **WHEN** the user executes `c-eyes sbom -h`
- **THEN** help text states SBOM is collection-only and does not support `-r/--riskanalyze`

#### Scenario: SBOM help states target exclusivity behavior
- **WHEN** the user executes `c-eyes sbom -h`
- **THEN** help text states exactly one target selector must be provided
- **AND** help text explains that `-p/--path` and `--image-target` are mutually exclusive
- **AND** help text states that `--target-type` can only be used with `--image-target`

### Requirement: Root help SHALL include benchmark command entry
Root help output SHALL list `benchmark` as a first-class command in the `COMMANDS` section.

#### Scenario: Root help lists benchmark command
- **WHEN** the user executes `c-eyes -h`
- **THEN** the `COMMANDS` section includes `benchmark`
- **AND** the command description indicates baseline/security benchmark checking capability

### Requirement: Benchmark help SHALL use structured English command template
The system SHALL provide `c-eyes benchmark -h` help in English with structured sections consistent with unified modules.

#### Scenario: Benchmark subcommand help uses standard sections
- **WHEN** the user executes `c-eyes benchmark -h`
- **THEN** help output includes `NAME`, `USAGE`, and `OPTIONS`
- **AND** options include `--template auto|windows|linux|euleros|kylin`

### Requirement: Benchmark help SHALL declare collection-only and privilege behavior
Benchmark help SHALL explicitly document collection-only behavior and required privilege level.

#### Scenario: Benchmark help states no risk-analysis support
- **WHEN** the user executes `c-eyes benchmark -h`
- **THEN** help text states `benchmark` does not support `-r/--riskanalyze`

#### Scenario: Benchmark help states privilege requirement
- **WHEN** the user executes `c-eyes benchmark -h`
- **THEN** help text states Windows requires administrator privilege
- **AND** help text states Linux-family systems require root privilege
