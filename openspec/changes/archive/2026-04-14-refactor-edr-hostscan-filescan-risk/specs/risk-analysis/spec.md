## MODIFIED Requirements

### Requirement: Risk input sources and mutual exclusion
The system SHALL support two risk-analysis invocation paths:
1) standalone global risk path (`edr -r` with explicit source), and
2) scan-chained risk path (`edr hostscan ... -r` or `edr filescan ... -r`) that uses scan output as risk input.
For standalone global risk path, the system SHALL accept exactly one source: `-input`, `-file`, `-dir`, `-pid`, or `-pname`.

#### Scenario: Reject mixed standalone input sources
- **WHEN** a user executes standalone risk analysis with both `-file` and `-dir`
- **THEN** CLI parsing fails with a Chinese validation error indicating sources are mutually exclusive

#### Scenario: Scan-chained risk does not require standalone source flags
- **WHEN** a user executes `edr hostscan --all -r`
- **THEN** risk analysis consumes hostscan output directly without requiring `-file/-dir/-pid/-pname`

### Requirement: Support analysis modes and parameters
The system SHALL support `local_only`, `cloud_only`, `fast`, `smart`, and `deep` analysis modes. The risk mode selector SHALL be exposed as `--risk-mode`, and default mode SHALL be `smart` when not provided.

#### Scenario: Default risk mode is smart
- **WHEN** a user executes `edr filescan -r` without `--risk-mode`
- **THEN** the effective risk analysis mode is `smart`

#### Scenario: Hostscan chained risk is constrained to local_only
- **WHEN** a user executes `edr hostscan -r --risk-mode deep`
- **THEN** the command fails with Chinese validation error because hostscan chained analysis only supports `local_only`

#### Scenario: Hybrid alias compatibility
- **WHEN** user input risk mode is `hybrid`
- **THEN** the system logs deprecation warning and executes mode `smart`

### Requirement: Scan-chained risk analysis handles empty input as valid no-data result
When risk analysis is invoked from chained scan mode, the system SHALL treat zero scan records as a valid no-data case and return an empty analysis list.

#### Scenario: Chained risk receives zero records
- **WHEN** user executes `edr hostscan --custom application -r` and scan output has zero records
- **THEN** risk analysis returns `[]` and command exits with code `0`

### Requirement: Cloud provider invalid-call suppression
The system SHALL reduce repeated invalid cloud calls without changing scoring logic:
1) providers without API keys are skipped during initialization;
2) providers returning auth/config class errors (e.g. missing key/401/403/unauthorized) are disabled for the current run.

#### Scenario: Provider missing API key
- **WHEN** risk analysis runs in cloud-involved mode and a provider has no API key
- **THEN** that provider is not initialized and no query is sent to it

#### Scenario: Provider auth failure during run
- **WHEN** a provider returns an auth/config class error on one query
- **THEN** subsequent queries in the same run skip that provider while other providers continue

### Requirement: Excel output
The system SHALL support exporting analysis results through the global output path selector `-o` with `.xlsx` suffix.

#### Scenario: Excel output requested
- **WHEN** the user executes risk analysis with `-o result.xlsx`
- **THEN** an Excel file is produced containing the analysis results for each scan target
