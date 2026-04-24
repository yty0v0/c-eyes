## MODIFIED Requirements

### Requirement: Provider-aware cloud weighting
Cloud score aggregation SHALL use security-first effective-provider semantics:
- Aggregation base score MUST be computed by `MAX(provider_score)` across effective providers, not by simple/weighted average.
- Effective providers MUST be limited to providers with successful query execution and valid verdict payload.
- Invalid states (`failed`, `timeout`, `pending`, `no_result`) MUST NOT dilute the base risk score.
- The analyzer MAY expose effective average as an observability metric, but final base score MUST remain max-score based.

#### Scenario: Single effective provider is not diluted by invalid peers
- **WHEN** VirusTotal returns score `53` and other providers are failed/timeout/no-result
- **THEN** cloud base score is `53` (not divided by total provider count)

#### Scenario: Multiple effective providers use highest score
- **WHEN** effective providers return scores `20`, `41`, and `78`
- **THEN** cloud base score is `78`

### Requirement: High-risk short-circuit verdict before final weighted scoring
The system SHALL evaluate a high-risk short-circuit stage after whitelist and before final weighted/cross-validation scoring.  
In addition to severity-based short-circuit, cloud override rules MUST apply:
- Label one-vote override: if any effective provider returns malicious threat label (for example `webshell`, `trojan`, `backdoor`, `ransom`), final risk level MUST be elevated to `高危`.
- Detection-threshold override: if any effective provider reports `malicious >= 3` or detection ratio `> 5%`, final result MUST NOT be `无风险`.

#### Scenario: Threat label one-vote triggers critical
- **WHEN** any effective provider returns label `trojan.webshell`
- **THEN** analyzer emits final high-severity verdict with risk level `高危`

#### Scenario: Detection threshold avoids no-risk verdict
- **WHEN** an effective provider returns `6/100` detections
- **THEN** analyzer result is elevated above `无风险`

### Requirement: Cloud aggregation output identity
In multi-platform cloud mode, output MUST explicitly describe aggregation identity and provider contribution status:
- `cloud_analysis.cloud_provider` MUST be `multi`
- `cloud_analysis.cloud_providers` MUST list providers that successfully contributed results
- `cloud_analysis.provider_outcome_card` MUST expose per-provider execution outcome (`success|no_result|failed|timeout|pending`)
- `cloud_analysis.effective_provider_count` MUST expose count of providers used in final max-score aggregation

#### Scenario: Mixed provider outcomes are observable
- **WHEN** only two providers succeed and three providers fail/timeout/pending
- **THEN** output includes contribution list and provider outcome card with all provider states

## ADDED Requirements

### Requirement: Cloud degraded-state fail-safe decision
The system SHALL use fail-safe behavior when cloud platform availability is degraded:
- If total selected providers are at least 5 and unresolved providers (`pending`, `failed`, `timeout`) are 3 or more, final verdict MUST NOT be `无风险`.
- If unresolved set contains pending providers, analyzer SHOULD output risk level `分析中`.
- Otherwise analyzer SHOULD output risk level `可疑-需本地核实` and require local/offline follow-up.

#### Scenario: Degraded cloud state returns pending
- **WHEN** 5 providers are selected and 3 providers are unresolved with at least one `pending`
- **THEN** final risk level is `分析中`

#### Scenario: Degraded cloud state without pending returns offline suspicious
- **WHEN** 5 providers are selected and unresolved providers are only `failed/timeout`
- **THEN** final risk level is `可疑-需本地核实`
