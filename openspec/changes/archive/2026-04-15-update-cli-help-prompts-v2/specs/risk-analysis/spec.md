## MODIFIED Requirements

### Requirement: Standalone risk help SHALL use categorized parameter layout
`edr -r -h` SHALL present an English structured help layout with `NAME`, `USAGE`, and `OPTIONS`, while preserving executable guidance for standalone risk analysis.

#### Scenario: Standalone risk help uses English sectioned layout
- **WHEN** the user executes `edr -r -h`
- **THEN** the output contains `NAME`, `USAGE`, and `OPTIONS` sections in English
- **AND** options include `-yara-rules`, `-analysis-max-duration`, `-cloud-upload`, `-process-memory`, and `--risk-mode`

### Requirement: Standalone risk help SHALL keep source exclusivity visible
Standalone risk help SHALL explicitly state that analysis source parameters are required and mutually exclusive, using the one-of-five set `-input/-file/-dir/-pid/-pname`.

#### Scenario: Standalone risk help states one-of-five source constraint
- **WHEN** the user executes `edr -r --help`
- **THEN** the usage text states one of `-input`, `-file`, `-dir`, `-pid`, or `-pname` must be provided
- **AND** `OPTIONS` includes descriptions for all five source parameters

