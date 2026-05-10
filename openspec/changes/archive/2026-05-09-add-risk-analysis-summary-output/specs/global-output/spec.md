## ADDED Requirements

### Requirement: Risk JSON export SHALL serialize summary and results together
When risk analysis is exported to JSON, the system SHALL write a single JSON object containing top-level `summary` and `results` fields instead of writing a bare result array.

#### Scenario: JSON file output uses wrapped risk payload
- **WHEN** the user executes a supported risk-analysis command with `-o risk.json`
- **THEN** the written file contains top-level `summary` and `results`

### Requirement: Risk Excel export SHALL append a summary sheet
When risk analysis is exported to Excel, the system SHALL preserve the main results sheet and append a separate `summary` sheet containing aggregated risk metrics.

#### Scenario: Excel file output includes risk summary sheet
- **WHEN** the user executes a supported risk-analysis command with `-o risk.xlsx`
- **THEN** the resulting workbook contains the main risk results sheet and a `summary` sheet
