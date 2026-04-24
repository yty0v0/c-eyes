## ADDED Requirements

### Requirement: Risk analysis SHALL stream risky findings during execution
When risk analysis is running (standalone or chained), the CLI MUST emit risky targets as incremental log lines instead of waiting for final file output.

#### Scenario: Chained filescan risk emits findings incrementally
- **WHEN** a user executes `c-eyes filescan ... -r` and multiple risky targets are detected
- **THEN** risky targets are printed one-by-one during analysis
- **AND** each line includes severity label, target path, file size, and hash context

#### Scenario: Standalone risk emit behavior matches chained mode
- **WHEN** a user executes standalone risk analysis with any supported source
- **THEN** risky findings are streamed during analysis using the same output contract as chained mode

### Requirement: Risk severity labels SHALL support terminal color with safe fallback
Risk streaming lines MUST classify levels into `HIGH`, `MEDIUM`, and `LOW`.  
If ANSI color is supported, labels MUST use red/orange/green respectively; otherwise labels MUST remain readable plain text.

#### Scenario: ANSI-capable terminal shows colored severity labels
- **WHEN** the runtime terminal supports ANSI color output
- **THEN** `HIGH` is rendered in red, `MEDIUM` in orange, and `LOW` in green

#### Scenario: Non-ANSI terminal keeps readable labels
- **WHEN** the runtime terminal does not support ANSI color output
- **THEN** labels remain visible as plain `[HIGH]`, `[MEDIUM]`, `[LOW]` text without control-sequence corruption

### Requirement: Risk analysis SHALL print non-zero severity summary at completion
After analysis completes, the CLI MUST print `Risk Summary` for streamed output, including total risky files and non-zero counts by severity band.

#### Scenario: Mixed severities print selective summary
- **WHEN** analysis completes with `HIGH > 0`, `MEDIUM = 0`, and `LOW > 0`
- **THEN** summary prints `Total risky files`, `HIGH`, and `LOW`
- **AND** summary omits `MEDIUM`

### Requirement: Risk analysis progress MUST remain a single stable row during streaming
Risk analysis progress updates MUST keep one active progress row even while streaming risk lines, and MUST avoid fragmented multi-row progress artifacts caused by long wrapped output lines.

#### Scenario: Long risk lines do not split progress into multiple active rows
- **WHEN** streamed findings contain long path/rule strings that wrap in terminal output
- **THEN** progress remains one active risk row
- **AND** risk lines are printed as standalone log lines without interleaving corruption
