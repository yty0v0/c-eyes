## ADDED Requirements

### Requirement: SBOM command SHALL enforce JSON output suffix with global -o
For `c-eyes sbom`, the system SHALL reuse global `-o/--output` as output path input and SHALL accept only `.json` suffix.

#### Scenario: SBOM explicit JSON output path
- **WHEN** the user executes `c-eyes sbom -p <path> -o sbom-result.json`
- **THEN** the system writes SBOM output to `sbom-result.json`

#### Scenario: SBOM explicit CSV output path is rejected
- **WHEN** the user executes `c-eyes sbom -p <path> -o sbom-result.csv`
- **THEN** the command returns an English argument error indicating SBOM output only supports `.json`

#### Scenario: SBOM explicit XLSX output path is rejected
- **WHEN** the user executes `c-eyes sbom -p <path> -o sbom-result.xlsx`
- **THEN** the command returns an English argument error indicating SBOM output only supports `.json`

### Requirement: SBOM command SHALL use result*.json auto naming when -o is omitted
When `c-eyes sbom` runs without `-o/--output`, the system SHALL auto-generate JSON output path in current working directory using `result.json`, `result1.json`, `resultN.json` incremental naming to avoid overwrite.

#### Scenario: First SBOM default output in empty directory
- **WHEN** the user executes `c-eyes sbom -p <path>` in a directory without existing `result*.json`
- **THEN** the system writes output to `result.json`

#### Scenario: Increment SBOM default output when result.json exists
- **WHEN** the user executes `c-eyes sbom -p <path>` and `result.json` already exists
- **THEN** the system writes output to `result1.json`

#### Scenario: Increment SBOM default output by maximum existing index
- **WHEN** the user executes `c-eyes sbom -p <path>` and directory already contains `result.json`, `result1.json`, and `result5.json`
- **THEN** the system writes output to `result6.json`
