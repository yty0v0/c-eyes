## ADDED Requirements

### Requirement: Eventlog SHALL provide a unified host log collection entry
The system SHALL provide `c-eyes eventlog` as a top-level command for host event-log collection and SHALL return paged aggregate output.

#### Scenario: Eventlog command runs with query parameters
- **WHEN** the user executes `c-eyes eventlog` with query parameters
- **THEN** the system returns a paged result object containing `total`, `pageNo`, `pageSize`, `hasMore`, and `rows`

#### Scenario: Eventlog command help is module-oriented
- **WHEN** the user executes `c-eyes eventlog -h`
- **THEN** the command prints English help sections consistent with other top-level modules

### Requirement: Eventlog collection MUST remain risk-analysis disabled
The system MUST treat `eventlog` as collection-only and MUST reject risk-analysis entry flags and risk-only parameters for this module.

#### Scenario: Eventlog rejects global risk enable flag
- **WHEN** the user executes `c-eyes eventlog -r`
- **THEN** the command returns an argument error indicating `eventlog` does not support `-r/--riskanalyze`
- **AND** exits with argument-error status

#### Scenario: Eventlog rejects risk-only options
- **WHEN** the user executes `c-eyes eventlog --risk-mode smart` or passes risk-only flags such as `-cloud-upload`/`-yara-rules`
- **THEN** the command returns an argument error
- **AND** does not execute event-log collection

### Requirement: Eventlog collectors MUST use in-process OS sources only
The system MUST collect host event logs using in-process OS APIs/readers and MUST NOT launch external command-line processes for log collection.

#### Scenario: Eventlog collection path uses internal collectors
- **WHEN** the system runs `eventlog` collection on Windows or Linux
- **THEN** collection is performed through platform-native APIs/readers without invoking external shell commands

### Requirement: Eventlog request validation and defaults SHALL be enforced
The system SHALL enforce bounded query inputs for event-log retrieval and SHALL provide a default time window when explicit time filters are omitted.

#### Scenario: Time range defaults are applied
- **WHEN** the user omits `startTime`, `endTime`, and `last`
- **THEN** the system resolves `endTime` to current time
- **AND** resolves `startTime` to `endTime - 24h`

#### Scenario: Time range is invalid
- **WHEN** `startTime > endTime`, or `startTime` is combined with `last`
- **THEN** the command returns an argument error

#### Scenario: Paging defaults are applied
- **WHEN** the user omits `pageNo` and `pageSize`
- **THEN** the system uses defaults `pageNo=1` and `pageSize=20`

#### Scenario: Page size exceeds upper bound
- **WHEN** the user sets `pageSize` beyond module maximum
- **THEN** the command returns an argument error

### Requirement: Eventlog filter semantics SHALL be deterministic
The system SHALL apply all provided structured filters as AND conditions, while array-valued filter fields SHALL match any listed value (OR within each field).

#### Scenario: Structured filters combine by AND
- **WHEN** the user provides multiple filters such as `sources`, `eventLevels`, and `processName`
- **THEN** only records satisfying all provided filter fields are returned

#### Scenario: Multi-value filter field matches any listed value
- **WHEN** the user provides multiple values for `sources` or `eventTypes`
- **THEN** records matching any value in that field are included

#### Scenario: Keyword filter applies as additional constraint
- **WHEN** the user provides `keyword` together with structured filters
- **THEN** records MUST satisfy structured filters and keyword matching

### Requirement: Eventlog normalization SHALL provide cross-platform stable enums
The system SHALL normalize platform-specific raw event metadata into stable output fields including `source`, `eventType`, `eventLevel`, `eventCode`, `eventAction`, and `result`.

#### Scenario: Known platform event type mapping
- **WHEN** a platform-native event maps to a known normalized event type
- **THEN** the returned row uses normalized values such as `process/file/network/registry/account/service/login/system/policy`

#### Scenario: Unknown platform event type mapping
- **WHEN** a platform-native event type has no known mapping
- **THEN** the returned row sets `eventType` to `other`

### Requirement: Eventlog sorting and pagination SHALL remain stable across pages
The system SHALL support deterministic ordering for paged retrieval and SHALL avoid page drift under equal primary sort values.

#### Scenario: Default sort order
- **WHEN** the user does not provide `sortBy` or `sortOrder`
- **THEN** records are sorted by `timestamp` in descending order

#### Scenario: Stable tie-break ordering
- **WHEN** multiple rows share identical primary sort values
- **THEN** the system applies deterministic tie-break ordering including `logId` to keep page boundaries stable

### Requirement: Eventlog output schema SHALL include normalized context fields
The system SHALL output event-log rows using a fixed schema with host context, actor/process context, target context, network context, and summary message fields.

#### Scenario: Eventlog result envelope fields are present
- **WHEN** any eventlog query completes successfully
- **THEN** output contains `total`, `pageNo`, `pageSize`, `hasMore`, and `rows`

#### Scenario: Eventlog row fields are present with fallback values
- **WHEN** a row is returned and some optional fields are unavailable
- **THEN** all schema keys remain present with `null` or empty-list fallback values as applicable

### Requirement: Eventlog raw payload handling SHALL be explicit and safe
The system SHALL exclude `rawContent` by default and SHALL include it only when explicitly requested.

#### Scenario: Raw payload disabled by default
- **WHEN** `includeRawContent` is omitted or `false`
- **THEN** output rows do not include raw payload content

#### Scenario: Raw payload requested
- **WHEN** `includeRawContent=true`
- **THEN** output rows include `rawContent` after redaction of known sensitive keys
- **AND** oversized raw payload is truncated with explicit truncation indication

### Requirement: Eventlog identity SHALL provide stable row-level identifiers
The system SHALL generate stable `logId` values for the same underlying event across repeated queries.

#### Scenario: Native event identifier exists
- **WHEN** the source provides a stable native event identifier
- **THEN** `logId` is derived from that native identifier and remains stable

#### Scenario: Native event identifier missing
- **WHEN** the source lacks stable native identifiers
- **THEN** `logId` is deterministically generated from normalized key fields
