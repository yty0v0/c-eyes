## MODIFIED Requirements

### Requirement: JSON output schema
The system SHALL output risk-analysis JSON as a top-level object containing `summary` and `results`. The `results` field SHALL contain analysis records with target metadata (`scan_id`, `timestamp`, `target_type`, `target_path`, `pid`, `file_size`, `hashes`) and analysis sections (`risk_assessment`, `local_analysis`, `cloud_analysis`).

#### Scenario: JSON output includes summary and results
- **WHEN** analysis completes for any supported risk-analysis invocation path
- **THEN** the JSON output contains top-level `summary` and `results` fields
- **AND** `results` contains all per-target analysis records

### Requirement: Excel output
The system SHALL support exporting analysis results to Excel, with one row per scan target and columns for the required metadata, `risk_score`, `risk_level`, and mode-specific fields.

#### Scenario: Excel output requested
- **WHEN** the user executes risk analysis with `-o result.xlsx`
- **THEN** an Excel file is produced containing the analysis results for each scan target
- **AND** the file includes a dedicated `summary` sheet for aggregated risk counts

### Requirement: Risk analysis SHALL print non-zero severity summary at completion
After analysis completes, the CLI MUST print `Risk Summary` for streamed output, including total risky files and non-zero counts by severity band.

#### Scenario: Mixed severities print selective summary
- **WHEN** analysis completes with `HIGH > 0`, `MEDIUM = 0`, and `LOW > 0`
- **THEN** summary prints `Total risky files`, `HIGH`, and `LOW`
- **AND** summary omits `MEDIUM`

## ADDED Requirements

### Requirement: Risk analysis SHALL expose structured summary aggregation
All currently supported risk-analysis entry paths SHALL produce a structured summary derived from final per-record risk levels. The summary SHALL cover standalone `c-eyes -r` and chained `c-eyes hostscan ... -r` / `c-eyes filescan ... -r`.

#### Scenario: Standalone risk output includes summary
- **WHEN** the user executes standalone risk analysis
- **THEN** the final output includes a structured summary derived from the completed analysis results

#### Scenario: Chained risk output includes summary
- **WHEN** the user executes `c-eyes filescan ... -r` or `c-eyes hostscan ... -r`
- **THEN** the final risk output includes the same structured summary model

### Requirement: Risk summary SHALL count operator-relevant non-safe categories
The risk summary SHALL report counts for `高危`, `高风险`, `中风险`, `低风险`, `分析中`, and `可疑-需本地核实`, plus total summarized results. `无风险` SHALL NOT be rendered as a summary metric.

#### Scenario: Safe results are excluded from rendered summary categories
- **WHEN** analysis completes with some records classified as `无风险`
- **THEN** those records are not shown as a dedicated summary metric

#### Scenario: Degraded cloud states remain distinct in summary
- **WHEN** analysis completes with records classified as `分析中` and `可疑-需本地核实`
- **THEN** the summary reports these categories separately rather than folding them into `高/中/低风险`

### Requirement: Terminal risk summary SHALL include risk-level and degraded-state categories
The terminal completion summary for risk analysis SHALL include total summarized results and non-zero category rows for `高危`, `高风险`, `中风险`, `低风险`, `分析中`, and `可疑-需本地核实`.

#### Scenario: Terminal summary shows degraded-state categories
- **WHEN** risk analysis completes and some records have `分析中` or `可疑-需本地核实`
- **THEN** the terminal summary prints those categories as independent rows when their counts are non-zero

### Requirement: Risk summary aggregation SHALL use final risk verdicts
Summary counts SHALL be derived from final `risk_assessment.risk_level` values after scoring, overrides, whitelist terminal decisions, and cloud degraded-state fail-safe logic have been applied.

#### Scenario: Critical override contributes to high-severity summary bucket
- **WHEN** a record is elevated to final risk level `高危` by cloud label override
- **THEN** the summary increments the `高危` count

#### Scenario: Failsafe pending contributes to pending summary bucket
- **WHEN** a record ends with final risk level `分析中`
- **THEN** the summary increments the `分析中` count
