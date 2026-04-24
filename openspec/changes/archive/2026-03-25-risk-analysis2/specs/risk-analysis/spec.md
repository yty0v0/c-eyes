## ADDED Requirements

### Requirement: Cloud upload is opt-in and gated as final defense
The system MUST keep cloud sample upload disabled by default. Cloud upload SHALL execute only when all final-defense conditions are satisfied: `-cloud-upload=true`, target is uploadable (readable file, not directory, size within limit), and pre-upload pipeline cannot produce a high-confidence conclusion.

#### Scenario: Upload remains disabled by default
- **WHEN** a user runs risk analysis without explicitly setting `-cloud-upload=true`
- **THEN** the analyzer MUST NOT submit files to cloud providers

#### Scenario: Upload triggers only when all gate conditions are met
- **WHEN** `-cloud-upload=true` and a record remains unresolved after pre-upload stages and the target file is uploadable
- **THEN** the analyzer submits the file to configured upload-capable providers as the final-defense action

### Requirement: Unified online-mode flow includes final upload gate
For `fast`, `smart`, `deep`, and `cloud_only` modes, the system SHALL execute mode-specific pre-upload stages first, then enter a shared decision stage to evaluate whether final-defense upload is required.

#### Scenario: Fast mode enters shared upload decision stage
- **WHEN** mode is `fast` and pre-upload stages complete
- **THEN** the analyzer evaluates the same final-defense upload gate used by other online modes

#### Scenario: Deep mode enters shared upload decision stage
- **WHEN** mode is `deep` and deep cloud dynamic checks finish without high-confidence conclusion
- **THEN** the analyzer evaluates the shared final-defense upload gate

### Requirement: High-confidence conclusions block upload
The system SHALL skip cloud upload if any high-confidence conclusion is already available from pre-upload stages, including whitelist allow/deny decision, high-confidence local malicious hit, high-confidence cloud hash hit, or explicit mode-level terminal verdict.

#### Scenario: Whitelist deny blocks upload
- **WHEN** whitelist decision is `deny`
- **THEN** the analyzer finalizes the verdict without submitting any file upload

#### Scenario: High-confidence cloud hash hit blocks upload
- **WHEN** cloud hash analysis reaches high-confidence malicious threshold before upload stage
- **THEN** the analyzer skips file upload and returns final result with existing evidence

### Requirement: Dynamic analysis duration budget by workload and upload pressure
When `-analysis-max-duration=0`, the system SHALL compute total analysis budget dynamically from workload size and upload pressure. The model MUST include `N` (total records), `U` (records entering upload stage), and `C` (upload concurrency), and MUST increase budget as `N` or `U` grows.

#### Scenario: Larger batch gets larger auto budget
- **WHEN** mode and runtime parameters are unchanged but record count increases from a small batch to a large batch
- **THEN** computed total budget increases accordingly instead of using a fixed timeout

#### Scenario: Upload-enabled run includes upload budget component
- **WHEN** `-cloud-upload=true` and `U>0`
- **THEN** computed total budget includes both base mode budget and upload budget component derived from submit/wait/poll parameters

### Requirement: User-defined max duration is a hard upper bound
If `-analysis-max-duration>0`, the system SHALL treat that value as a hard upper limit for the entire analysis run, regardless of auto-calculated dynamic budget.

#### Scenario: User override caps computed budget
- **WHEN** auto-calculated budget exceeds user-provided `-analysis-max-duration`
- **THEN** the analyzer enforces the user-provided duration as the effective maximum

### Requirement: Mode-specific default upload wait for zero value
When `-cloud-upload-wait=0`, the system SHALL resolve wait timeout by analysis mode defaults: `fast=10s`, `smart=3m`, `cloud_only=4m`, and `deep=6m`.

#### Scenario: Zero wait resolves to fast default
- **WHEN** mode is `fast` and `-cloud-upload-wait=0`
- **THEN** effective wait timeout is `10s`

#### Scenario: Zero wait resolves to deep default
- **WHEN** mode is `deep` and `-cloud-upload-wait=0`
- **THEN** effective wait timeout is `6m`

### Requirement: Provider-aware upload strategy and throttling
The system SHALL support provider-specific upload policy in multi-provider mode: VirusTotal, Triage, and Hybrid Analysis are upload-capable; MalwareBazaar remains hash-query-only by default; OTX remains hash-intel-only. Upload scheduling MUST enforce provider-level concurrency and rate limits.

#### Scenario: Upload-capable providers receive submissions
- **WHEN** final-defense upload is triggered and provider config is enabled
- **THEN** submissions are sent to VirusTotal, Triage, and Hybrid Analysis under their configured limits

#### Scenario: Hash-only providers are not used for file upload
- **WHEN** final-defense upload is triggered
- **THEN** MalwareBazaar and OTX are not given file upload tasks unless explicitly supported by policy

### Requirement: High-risk short-circuit verdict before final weighted scoring
The system SHALL evaluate a high-risk short-circuit stage after whitelist and before final weighted/cross-validation scoring. If local YARA-X reports high-confidence high severity or any cloud provider reports high-risk score, the analyzer MUST output high-risk verdict directly and skip remaining weighted path.

#### Scenario: Local high-severity YARA match short-circuits
- **WHEN** local YARA-X result indicates high-confidence high severity threshold
- **THEN** analyzer returns high-risk verdict without executing remaining weighted scoring path

#### Scenario: Cloud high-risk provider score short-circuits
- **WHEN** any provider score reaches configured high-risk threshold during cloud stages
- **THEN** analyzer short-circuits to high-risk verdict and returns supporting evidence

### Requirement: Upload execution fields are included in analysis output
The analysis output SHALL include structured upload observability fields: `cloud_upload_enabled`, `cloud_upload_attempted`, `cloud_upload_status`, `cloud_upload_reason`, `cloud_upload_providers`, `cloud_upload_tasks`, and `cloud_upload_duration_ms`.

#### Scenario: Upload skipped is explicitly observable
- **WHEN** upload gate is not satisfied
- **THEN** output sets upload fields to indicate skipped status and includes machine-readable reason

#### Scenario: Upload completed includes task-level details
- **WHEN** at least one provider upload task completes
- **THEN** output includes provider/task identifiers, status, optional score/link, and total upload duration
