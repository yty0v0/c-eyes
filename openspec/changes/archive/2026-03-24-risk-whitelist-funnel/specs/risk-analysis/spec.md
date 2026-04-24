## MODIFIED Requirements

### Requirement: Risk input sources and mutual exclusion
The system SHALL support exactly one risk-analysis input source per execution: `-input`, `-file`, `-dir`, `-pid`, or `-pname`.
The `-dir` source SHALL recursively traverse child files by default and MUST NOT require a separate `-r` flag.

#### Scenario: Directory source without extra recursive flag
- **WHEN** a user executes risk analysis with `-dir D:\\samples`
- **THEN** the analyzer accepts the request and recursively collects files under the directory

#### Scenario: Legacy recursive flag is rejected
- **WHEN** a user provides `-dir D:\\samples -r`
- **THEN** CLI parsing fails because `-r` is no longer a defined risk-analysis flag

### Requirement: Support analysis modes and parameters
The system SHALL support `local_only`, `cloud_only`, `fast`, `smart`, and `deep` analysis modes. The `risk_assessment.analysis_mode` field MUST reflect the effective mode. Legacy `hybrid` input MUST be treated as deprecated alias of `smart`.

#### Scenario: Smart analysis mode
- **WHEN** analysis is executed with mode `smart`
- **THEN** the output mode is `smart` and the pipeline executes whitelist funnel, local pre-scan, and context-aware cloud path

#### Scenario: Deep analysis mode
- **WHEN** analysis is executed with mode `deep`
- **THEN** the pipeline executes `smart` behavior first and enters deep dynamic cloud stage only when still unresolved

#### Scenario: Hybrid alias compatibility
- **WHEN** user input mode is `hybrid`
- **THEN** the system logs deprecation warning and executes mode `smart`

### Requirement: Legacy mode and provider selector flags are removed
Mode/provider selection SHALL be controlled by `-mode` and cloud config only.
Legacy flags `-local`, `-cloud`, and `-cloud-provider` MUST be rejected as undefined CLI flags.

#### Scenario: Legacy local selector is rejected
- **WHEN** a user executes risk analysis with `-input scan.json -local`
- **THEN** CLI parsing fails because `-local` is not defined

#### Scenario: Legacy cloud-provider selector is rejected
- **WHEN** a user executes risk analysis with `-input scan.json -cloud-provider triage`
- **THEN** CLI parsing fails because `-cloud-provider` is not defined

### Requirement: Local engine availability and mode fallback policy
The system SHALL enforce strict local behavior when YARA-X is unavailable:
- `local_only`: fail fast with a clear error.
- `smart`, `deep`, and `fast`: continue with available whitelist/cloud path and log warning that local YARA fallback is disabled.

#### Scenario: Local-only without YARA-X
- **WHEN** mode is `local_only` and local YARA-X engine cannot initialize
- **THEN** command exits with explicit error indicating local analysis cannot continue

#### Scenario: Smart without YARA-X
- **WHEN** mode is `smart` and local YARA-X engine cannot initialize
- **THEN** command continues with whitelist and cloud path and logs a warning

## ADDED Requirements

### Requirement: Chinese help output for CLI commands
The system SHALL provide Chinese help text for root and subcommands when users invoke `-h` or `--help`.

#### Scenario: Risk analyze help is localized
- **WHEN** a user executes `edr risk analyze -h`
- **THEN** help headers and option descriptions are displayed in Chinese

### Requirement: Smart/deep whitelist gate before cloud queries
The system SHALL evaluate whitelist funnel before local YARA/cloud operations in `smart` and `deep` modes.

#### Scenario: Whitelist allow skips cloud
- **WHEN** whitelist engine returns `allow`
- **THEN** system skips cloud query and returns safe verdict with whitelist evidence

#### Scenario: Whitelist deny short-circuits analysis
- **WHEN** whitelist engine returns `deny`
- **THEN** system returns high-risk verdict and does not execute cloud query

### Requirement: Fast whitelist funnel decision semantics
The system SHALL run low-cost whitelist checks in `fast` mode before cloud/local fallback, and decision semantics MUST be:
- `allow` => final risk score `0` (safe)
- `deny` => final risk score `100` (high risk)
- `continue` => proceed to fast cloud lookup and local YARA fallback path

#### Scenario: Fast allow short-circuit
- **WHEN** `fast` whitelist decision is `allow`
- **THEN** analysis ends without cloud query/local fallback and final score is `0`

#### Scenario: Fast deny short-circuit
- **WHEN** `fast` whitelist decision is `deny`
- **THEN** analysis ends immediately and final score is `100`

#### Scenario: Fast continue enters downstream stages
- **WHEN** `fast` whitelist decision is `continue`
- **THEN** system enters `fast_lookup` and may enter `fast_fallback_yara` if needed

### Requirement: Local YARA severity fallback for matched rules
When local YARA-X reports a rule match and metadata `severity` is missing, invalid, or `<=0`, the system SHALL assign a fallback severity derived from rule name/tags to prevent zero-risk underestimation.

#### Scenario: Known high-risk family without severity metadata
- **WHEN** a matched rule name/tag indicates a known high-risk family (for example `webshell` or `ransom`)
- **THEN** output `yara_results[].severity` is set to a high fallback band (not `0`)

#### Scenario: Unclassified matched rule without severity metadata
- **WHEN** a matched rule has no explicit severity and no high-risk family signal
- **THEN** output `yara_results[].severity` uses a non-zero default matched severity

### Requirement: VT free-tier token bucket protection
For fast and contextual cloud stages that call VirusTotal, the system SHALL enforce token bucket rate limiting with a default budget equivalent to 4 requests per minute.

#### Scenario: Token bucket exhausted
- **WHEN** VT token bucket has no available token
- **THEN** VT request is not sent and analysis follows degrade path without blocking

### Requirement: Progress visibility for scans
The system SHALL provide observable progress for `process scan`, `file scan`, and `risk analyze` executions without breaking machine-readable stdout payloads.

#### Scenario: Progress with JSON output
- **WHEN** user runs scan command with JSON output to stdout
- **THEN** progress is emitted to stderr and stdout remains valid JSON
