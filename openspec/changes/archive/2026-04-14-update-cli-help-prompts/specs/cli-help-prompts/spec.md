## ADDED Requirements

### Requirement: Root help SHALL follow fixed operation-oriented template
When users run `edr -h` or `edr --help`, the system SHALL output a concise help template that focuses on runnable command examples instead of generic command taxonomy.

#### Scenario: Root help uses prescribed sections and examples
- **WHEN** the user executes `edr -h`
- **THEN** the output includes hostscan risk/basic examples, filescan risk/basic examples, local full/smart examples, direct risk-source examples, and output settings in the specified order

### Requirement: Root help SHALL include risk source parameter details
Root help SHALL include the five direct risk source parameters (`-input/-file/-dir/-pid/-pname`) and their meanings under the direct analysis source section.

#### Scenario: Root help lists five source options
- **WHEN** the user executes `edr --help`
- **THEN** the output includes descriptions for `-input`, `-file`, `-dir`, `-pid`, and `-pname`

