## ADDED Requirements

### Requirement: Filescan SHALL provide a software module for software inventory collection
The system SHALL support `software` as a selectable `filescan` web-mode module, available through `edr filescan --custom software` and included in `edr filescan --all`.

#### Scenario: Custom software module execution
- **WHEN** the user executes `edr filescan --custom software`
- **THEN** the system runs software inventory collection and returns aggregated scan rows for the software module

#### Scenario: All-mode includes software module
- **WHEN** the user executes `edr filescan --all`
- **THEN** the filescan module set includes `software` together with other web-mode modules

### Requirement: Software collection MUST use in-process static-plus-dynamic sources
The system MUST collect software information on Windows and Linux using in-process OS/file/runtime metadata sources and MUST NOT launch external command-line processes for software enumeration.

#### Scenario: Cross-platform non-command collection
- **WHEN** software collection runs on Windows or Linux
- **THEN** the collector reads OS metadata, configuration/package evidence, and process metadata in-process without launching external enumeration commands

#### Scenario: Service-first plus install-evidence collection
- **WHEN** software collection is executed
- **THEN** the collector prioritizes service/runtime-correlated software evidence and may append install-evidence rows only when `binPath` or `configPath` can be normalized

### Requirement: Software query filters SHALL support requested parameters
The system SHALL support optional filters `groups`, `hostname`, `ip`, `name`, `version`, `binPath`, and `configPath`.

#### Scenario: Host filters are applied with filescan web-module semantics
- **WHEN** the user provides `groups`, `hostname`, or `ip`
- **THEN** the system applies the same host-level semantics used by existing filescan web modules (`groups` intersection, fuzzy hostname/ip matching)

#### Scenario: Software string filters are fuzzy
- **WHEN** the user provides `name`, `binPath`, or `configPath`
- **THEN** matching is case-insensitive fuzzy containment against normalized software rows

#### Scenario: Version list filter is structured
- **WHEN** the user provides `version` array values
- **THEN** the system returns rows whose normalized `version` matches any provided version value using case-insensitive comparison

### Requirement: Software output schema SHALL be software-centric with aggregated processes
The system SHALL output software rows containing stable keys: `externalIpList`, `internalIpList`, `bizGroupId`, `bizGroup`, `remark`, `hostTagList`, `hostname`, `name`, `version`, `uname`, `binPath`, `configPath`, and `processes`.

#### Scenario: Contract keys are present
- **WHEN** any software row is returned
- **THEN** all contract keys are present with null or empty-list fallback when data is unavailable

#### Scenario: Multiple related processes stay in one software row
- **WHEN** multiple runtime processes are correlated to the same software identity
- **THEN** the output keeps one software row and stores related runtime entries in `processes[]` items containing `pid`, `name`, and `uname`

### Requirement: Software host IP fields MUST be list-based without scalar IP fields
The system MUST represent host IP data for software rows using `externalIpList` and `internalIpList`, and MUST NOT expose scalar `externalIp` or `internalIp` fields for this capability.

#### Scenario: Multi-interface host IP output
- **WHEN** a host has multiple internal or external IP addresses
- **THEN** software rows include all values in list form under `internalIpList` and `externalIpList`

### Requirement: Software capability scope MUST remain information collection only
The system MUST limit software module output to inventory metadata and MUST NOT include risk verdict, risk score, or remediation fields.

#### Scenario: No risk-analysis fields in software output
- **WHEN** software collection completes without `-r`
- **THEN** output rows include software asset metadata only and exclude risk-analysis conclusion fields
