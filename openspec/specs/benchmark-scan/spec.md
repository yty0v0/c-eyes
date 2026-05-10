# Benchmark Scan

## Purpose

Define the benchmark baseline-check command, its template routing, privilege requirements, native collector behavior, and report-oriented output expectations.

## Requirements

### Requirement: Benchmark command SHALL provide a collection-only baseline module
The system SHALL provide `c-eyes benchmark` as a unified baseline-check command and MUST keep this command collection-only without risk-analysis chaining.

#### Scenario: Run baseline collection through benchmark command
- **WHEN** the user executes `c-eyes benchmark`
- **THEN** the system runs baseline-check collection for the selected template
- **AND** the command returns benchmark results and summary metrics

#### Scenario: Reject risk-analysis flags for benchmark command
- **WHEN** the user executes `c-eyes benchmark -r`
- **THEN** the command returns an English argument error indicating `benchmark` does not support `-r/--riskanalyze`

### Requirement: Benchmark command SHALL support template routing and baseline-level selection
The system SHALL support `--template auto|windows|linux|euleros|kylin` and MUST use `auto` when the option is omitted. The system SHALL support `--baseline-level 1|2|3|4` and MUST use `1` when the option is omitted.

#### Scenario: Auto template selects Windows template
- **WHEN** the user executes `c-eyes benchmark` on Windows runtime
- **THEN** benchmark selects `windows` automatically

#### Scenario: Auto template selects Linux-family template by distro
- **WHEN** the user executes `c-eyes benchmark` on Linux runtime
- **THEN** benchmark selects `euleros` or `kylin` when distro signals match
- **AND** otherwise selects `linux`

#### Scenario: Explicit template must match current runtime family
- **WHEN** the user executes `c-eyes benchmark --template linux` on Windows runtime
- **THEN** benchmark rejects the command with an English error indicating the template does not match the current system

#### Scenario: Baseline level defaults to level 1
- **WHEN** the user executes `c-eyes benchmark` without `--baseline-level`
- **THEN** benchmark uses baseline level `1`

#### Scenario: Explicit baseline level selects level-specific rule set
- **WHEN** the user executes `c-eyes benchmark --template linux --baseline-level 3`
- **THEN** benchmark uses the Linux template with the level-3 benchmark rule set and metadata

### Requirement: Benchmark command SHALL enforce elevated privilege
The benchmark module MUST fail fast when elevated privilege is not available.

#### Scenario: Windows non-administrator execution is rejected
- **WHEN** a non-administrator user executes `c-eyes benchmark` on Windows
- **THEN** the command exits with an English permission error indicating administrator privilege is required

#### Scenario: Linux-family non-root execution is rejected
- **WHEN** a non-root user executes `c-eyes benchmark` on Linux, EulerOS, or Kylin
- **THEN** the command exits with an English permission error indicating root privilege is required

### Requirement: Benchmark runtime SHALL use native collectors and YAML rule metadata
The benchmark runtime SHALL use Go-native collectors and YAML-defined rule metadata for `windows`, `linux`, `euleros`, and `kylin` templates across all supported baseline levels while preserving each template's benchmark semantics. The runtime MUST NOT invoke external commands, shell pipelines, or vendor benchmark scripts to obtain benchmark facts for any template-level check.

#### Scenario: Windows benchmark runs without command or script collection
- **WHEN** the user executes `c-eyes benchmark --template windows --baseline-level 4`
- **THEN** benchmark completes using Go-native Windows collectors and YAML rule metadata
- **AND** benchmark does not invoke external `.exe`, `.cmd`, `.bat`, `.ps1`, `.vbs`, `.pl`, or similar command/script collectors to obtain Windows baseline facts

#### Scenario: Linux-family benchmark uses native fact collection for any level
- **WHEN** the user executes `c-eyes benchmark --template linux --baseline-level 3`
- **THEN** benchmark collects Linux baseline facts from in-process native readers, OS files, or platform APIs
- **AND** benchmark does not invoke shell commands or packaged benchmark scripts to obtain those facts

#### Scenario: EulerOS and Kylin templates stay on the same native-only contract
- **WHEN** the user executes `c-eyes benchmark --template euleros` or `c-eyes benchmark --template kylin`
- **THEN** the selected template uses the same native-only fact-collection contract as `linux`
- **AND** no template-specific benchmark fact is sourced from command execution or vendor script replay

### Requirement: Benchmark native policy results SHALL prefer trustworthy native sources
Benchmark policy evaluation MUST return determinate results when the operating system exposes a trustworthy native source for the requested field. The implementation MUST NOT degrade such checks to `unknown` because of avoidable access-mask mistakes, incorrect native API selection, or other implementation-level collector defects.

#### Scenario: Native Windows password policy fields return determinate values
- **WHEN** benchmark evaluates Windows security policy fields such as `PasswordComplexity`, `AllowAdministratorLockout`, or `ClearTextPassword`
- **THEN** the values are collected from trustworthy native Windows security interfaces
- **AND** the resulting row values reflect the effective local security policy instead of `unknown`

#### Scenario: Missing trustworthy native source remains unknown without command fallback
- **WHEN** a benchmark field has no sufficiently trustworthy native source on the current platform
- **THEN** benchmark marks that row as undetermined/`unknown`
- **AND** benchmark does not fall back to external command execution, shell parsing, or vendor script replay to synthesize a value

#### Scenario: Native collector semantics remain comparable to platform truth
- **WHEN** maintainers validate native benchmark output against platform policy exports or equivalent operating-system truth sources
- **THEN** the native collector values match the effective policy semantics for the same fields
- **AND** benchmark rule evaluation produces the same pass/fail outcome those effective values imply

### Requirement: Benchmark source and packaged assets SHALL NOT leak original script artifacts
The benchmark implementation MUST NOT retain or distribute original benchmark script artifacts in source asset directories, embedded asset sets, or packaged outputs.

#### Scenario: Benchmark asset directories exclude original script files
- **WHEN** a maintainer inspects benchmark asset directories in source form
- **THEN** the directories do not contain original benchmark `.pl`, `.sh`, `.vbs`, or similar script payloads
- **AND** benchmark assets only retain approved non-script metadata such as YAML rule files or explicit documentation

#### Scenario: Embedded benchmark assets exclude original script files
- **WHEN** the project embeds benchmark assets into the binary
- **THEN** the embed set excludes original benchmark script artifacts
- **AND** only approved non-script benchmark assets are embedded

#### Scenario: Packaged benchmark output does not expose original script assets
- **WHEN** the project produces a distributable source archive or binary package
- **THEN** the package does not include original benchmark script artifacts
- **AND** the package does not include instructions that require copying or executing original benchmark scripts on target hosts

#### Scenario: Benchmark rule metadata is applied
- **WHEN** a benchmark row matches a configured YAML rule
- **THEN** the row includes readable rule metadata such as check name, expected value, severity, and recommendation

#### Scenario: Linux-family native benchmark path is used
- **WHEN** the user executes `c-eyes benchmark` on Linux-family runtime
- **THEN** benchmark uses the Unix native benchmark path
- **AND** output rows still include readable rule metadata and normalized benchmark fields

### Requirement: Benchmark exported result rows SHALL prioritize report readability
The system SHALL export benchmark rows in a concise report-oriented shape for CSV/XLSX output.

#### Scenario: Benchmark CSV/XLSX use concise Chinese report columns
- **WHEN** the user exports benchmark results to `.csv` or `.xlsx`
- **THEN** the results sheet uses concise Chinese columns for report reading
- **AND** the exported main table prioritizes check identifier, check name, category, expected baseline, actual result, display status, severity, recommendation, and evidence summary

#### Scenario: Display statuses are human-readable
- **WHEN** benchmark rows are exported for report consumption
- **THEN** pass/fail/informational/undetermined states are mapped to human-readable display labels

### Requirement: Benchmark SHALL normalize exported display identifiers
The system SHALL keep internal benchmark identifiers compatible with implementation needs while using normalized display identifiers in exported report views.

#### Scenario: Windows informational rows use WIN-DISP identifiers
- **WHEN** a Windows informational benchmark row is exported
- **THEN** its exported display identifier uses `WIN-DISP-*` format

#### Scenario: Windows rule rows use WIN-prefixed identifiers
- **WHEN** a Windows rule benchmark row is exported
- **THEN** its exported display identifier uses `WIN-*` format

### Requirement: Benchmark SHALL not export retained raw XML references
The benchmark module SHALL NOT expose retained raw XML file references in exported benchmark payloads.

#### Scenario: Exported benchmark payload excludes raw XML paths
- **WHEN** benchmark returns JSON/CSV/XLSX output
- **THEN** result rows do not include `raw_xml_path`
- **AND** the top-level payload does not include `raw_xml_paths`

#### Scenario: Runtime XML is not retained as exported evidence copy
- **WHEN** benchmark completes execution
- **THEN** any internal XML used for parsing is not retained as a persistent exported evidence copy

### Requirement: Benchmark summary language SHALL differ by destination
The system SHALL keep terminal benchmark summary output in English and SHALL use Chinese labels for exported summary files/sheets.

#### Scenario: Terminal benchmark summary remains English
- **WHEN** benchmark finishes in the terminal
- **THEN** the benchmark summary section uses English metric labels

#### Scenario: Exported benchmark summary is Chinese
- **WHEN** benchmark summary is written to CSV sidecar or XLSX summary sheet
- **THEN** summary headers and metric names use Chinese labels
