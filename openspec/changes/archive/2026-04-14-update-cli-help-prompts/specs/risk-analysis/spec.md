## ADDED Requirements

### Requirement: Standalone risk help SHALL use categorized parameter layout
`edr -r -h` help output SHALL group options into source parameters, analysis mode parameters, and analysis-enhancement parameters.

#### Scenario: Standalone risk help shows grouped categories
- **WHEN** the user executes `edr -r -h`
- **THEN** the output groups risk options by source, mode, and enhancement instead of printing only flat default flag output

### Requirement: Standalone risk help SHALL keep source exclusivity visible
Standalone risk help SHALL explicitly document that risk sources are required and mutually exclusive (`-input/-file/-dir/-pid/-pname` one-of-five).

#### Scenario: Standalone risk help states one-of-five source constraint
- **WHEN** the user executes `edr -r --help`
- **THEN** the output states the five source flags and indicates exactly one must be provided

