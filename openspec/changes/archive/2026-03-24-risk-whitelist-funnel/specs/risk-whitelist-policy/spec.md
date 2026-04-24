## ADDED Requirements

### Requirement: Multi-dimensional whitelist funnel and precedence
The system SHALL execute whitelist decisions using a deterministic funnel before expensive analysis steps. Decision precedence MUST be `deny > allow > continue`.

#### Scenario: Deny precedence overrides allow evidence
- **WHEN** a sample is signed by a trusted publisher but also matches a revoked/stolen certificate or BYOVD deny rule
- **THEN** the system returns `deny` and MUST NOT treat the sample as whitelisted

#### Scenario: Continue path enters existing analysis
- **WHEN** no whitelist allow or deny condition matches
- **THEN** the system returns `continue` and proceeds to local YARA-X and stage-appropriate cloud analysis

### Requirement: Trusted publisher allowlist with strict trust boundary
The system SHALL NOT trust all valid signatures. It MUST allowlist only enterprise-approved publishers and products.

#### Scenario: Valid signature from untrusted publisher
- **WHEN** `signature_valid=true` but signer is not in trusted publisher policy
- **THEN** the sample is not auto-whitelisted and evaluation continues

#### Scenario: Valid signature from trusted publisher
- **WHEN** signer and product both match trusted publisher policy
- **THEN** the sample is eligible for whitelist `allow` unless any deny rule matches

### Requirement: Certificate denylist enforcement
The system SHALL block samples signed with revoked, stolen, or explicitly denied certificates even if signature validation is successful.

#### Scenario: Stolen certificate hit
- **WHEN** certificate thumbprint or serial matches denylist
- **THEN** verdict is `deny` and risk analysis marks the sample high risk

### Requirement: BYOVD vulnerable driver denylist
The system SHALL deny known vulnerable drivers (BYOVD) by hash/signature/driver identity using maintained blocklists.

#### Scenario: Vulnerable driver hash match
- **WHEN** driver hash matches vulnerable driver blocklist
- **THEN** verdict is `deny` regardless of signature validity

### Requirement: Authority hash repositories for allow decisions
The system SHALL support authority hash repositories including NSRL and enterprise baseline hashes.

#### Scenario: NSRL hash match
- **WHEN** sample SHA-256 exists in NSRL authority store
- **THEN** verdict is `allow` with source `nsrl`

#### Scenario: Enterprise baseline hash match
- **WHEN** sample SHA-256 exists in enterprise baseline repository
- **THEN** verdict is `allow` with source `enterprise_baseline`

### Requirement: Local reputation cache with TTL
The system SHALL maintain a local reputation cache for recently validated safe hashes with configurable TTL.

#### Scenario: Cache hit within TTL
- **WHEN** sample hash exists in safe cache and entry is not expired
- **THEN** verdict is `allow` with source `local_cache`

#### Scenario: Cache expired
- **WHEN** cached safe entry is expired
- **THEN** cache entry is ignored and funnel evaluation continues

### Requirement: Path and context combination rules
The system SHALL evaluate path and context jointly for whitelist decisions and MUST NOT rely on path-only trust.

#### Scenario: System32 plus Microsoft valid signature
- **WHEN** executable path is under `C:\Windows\System32\` and signature is valid and trusted Microsoft publisher
- **THEN** sample is eligible for `allow`

#### Scenario: System32 without trusted signature
- **WHEN** executable path is under `C:\Windows\System32\` but trusted signature conditions are not met
- **THEN** sample is not auto-whitelisted and continues to deeper analysis

#### Scenario: Business path plus parent process context
- **WHEN** executable path is under configured business directory and parent process context matches configured business parent policy
- **THEN** sample is eligible for `allow`

### Requirement: LOLBin command-line-level exceptions
For dual-use binaries (`powershell.exe`, `cmd.exe`, `wmic.exe`, `certutil.exe`, etc.), whitelist SHALL be evaluated at command-line policy level instead of file level.

#### Scenario: Approved operational command
- **WHEN** LOLBin path is trusted and full command line matches approved command policy
- **THEN** sample is eligible for `allow`

#### Scenario: Non-approved LOLBin command
- **WHEN** LOLBin binary is trusted but command line does not match approved command policy
- **THEN** sample is not whitelisted and MUST proceed to YARA/cloud analysis

### Requirement: Whitelist decision auditability
The system SHALL record whitelist decision evidence in analysis output for audit and tuning.

#### Scenario: Allow decision output
- **WHEN** whitelist returns `allow`
- **THEN** output includes decision source, policy id, reason, and evidence summary

#### Scenario: Deny decision output
- **WHEN** whitelist returns `deny`
- **THEN** output includes deny reason and matched deny policy evidence
