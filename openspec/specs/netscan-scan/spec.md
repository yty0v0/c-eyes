# Netscan Scan

## Purpose

Define the unified `c-eyes netscan` internal network discovery behavior, including collection-only guardrails, capability-aware probing, adaptive runtime controls, deterministic asset identity, and normalized output/filter semantics.

## Requirements

### Requirement: Netscan SHALL provide a top-level internal host discovery entry
The system SHALL provide `c-eyes netscan` as a top-level module aligned with `hostscan`, `filescan`, and `eventlog`, and SHALL run network asset discovery through in-process collectors/probers.

#### Scenario: Netscan command executes as standalone module
- **WHEN** the user executes `c-eyes netscan` with valid execute options
- **THEN** the command runs network discovery and returns normalized asset output

### Requirement: Netscan MUST remain collection-only and reject risk-analysis flags
The system MUST treat `netscan` as collection-only and MUST reject `-r/--riskanalyze` and risk-only options for this module.

#### Scenario: Netscan rejects global risk flag
- **WHEN** the user executes `c-eyes netscan -r`
- **THEN** the command returns an argument error in English indicating `netscan` does not support `-r/--riskanalyze`
- **AND** the scan does not start

#### Scenario: Netscan rejects risk-only options
- **WHEN** the user executes `c-eyes netscan --risk-mode smart` or passes risk-only flags such as `-cloud-upload` or `-yara-rules`
- **THEN** the command returns an argument error in English
- **AND** no network probing is executed

### Requirement: Netscan execute-target resolution SHALL be deterministic and bounded
The system SHALL accept targets from `target` and `targetFile`, support CIDR/IP/range/list input, merge and deduplicate them, apply `exclude` before probing, and enforce `maxTargets` as a hard safety limit.

#### Scenario: Target inputs are merged and deduplicated
- **WHEN** the user provides overlapping entries in both `target` and `targetFile`
- **THEN** the runtime merges all targets into one deduplicated target set before scanning

#### Scenario: Exclusion is applied before probing
- **WHEN** the user provides `exclude` values that overlap resolved targets
- **THEN** excluded addresses are removed from the final probe plan

#### Scenario: Target count exceeds configured safety cap
- **WHEN** the resolved target count is greater than `maxTargets`
- **THEN** the command returns an argument error in English and refuses execution

#### Scenario: No explicit target defaults to primary-interface C-segment discovery
- **WHEN** the user omits both `target` and `targetFile`
- **THEN** the runtime resolves default targets from the primary interface IPv4 C-segment (`x.x.x.1~254`)
- **AND** it does not fan out across all private interfaces by default

#### Scenario: UTF-8 BOM comments in targetFile are ignored
- **WHEN** a `targetFile` contains a BOM-prefixed comment line like `\uFEFF# comment`
- **THEN** the parser treats it as a comment and skips it
- **AND** no unsupported-target error is raised for that line

### Requirement: Netscan SHALL support nine probe modes with capability-aware behavior
The system SHALL support mode selection from `A, ICP, ICA, ICT, T, TS, U, N, O` (single or comma-separated), and SHALL execute each selected mode only where platform/protocol capability is available.

#### Scenario: Mixed mode request executes supported modes and skips unsupported modes
- **WHEN** the user requests multiple modes and one mode is not supported for the target protocol or platform
- **THEN** supported modes continue to run
- **AND** unsupported modes are skipped with explicit English warnings

#### Scenario: Privilege-required mode fails with explicit error
- **WHEN** a selected mode requires elevated privileges and the runtime lacks required privileges
- **THEN** that mode reports an explicit English permission error
- **AND** the error message identifies the mode and required privilege condition

### Requirement: A mode fallback behavior SHALL be explicit in non-ARP-compatible contexts
The system SHALL make `A` mode behavior explicit when native ARP probing cannot be applied directly, and SHALL surface warnings in English.

#### Scenario: A mode skips non-IPv4 targets with warning
- **WHEN** `scanMode` includes `A` and target is IPv6
- **THEN** `A` mode is skipped for that target
- **AND** output includes an explicit English warning

#### Scenario: A mode compatibility fallback is warning-visible
- **WHEN** `scanMode` includes `A` and current build/runtime uses compatibility probing instead of native ARP
- **THEN** output includes explicit English warning text describing compatibility fallback
- **AND** mode-scoped output semantics remain enforced (`A`-only runs do not surface port findings)

### Requirement: Netscan SHALL support IPv4 and capability-scoped IPv6 probing
The system SHALL scan IPv4 targets by default and SHALL include IPv6 targets when `ipv6=true`; for IPv6 targets it SHALL run only modes that support IPv6 in the current runtime and SHALL emit English warnings for skipped modes.

#### Scenario: IPv6 disabled
- **WHEN** `ipv6` is omitted or `false`
- **THEN** IPv6 targets are not probed

#### Scenario: IPv6 enabled with partially supported modes
- **WHEN** `ipv6=true` and selected modes include both IPv6-capable and IPv6-incapable modes
- **THEN** IPv6-capable modes run against IPv6 targets
- **AND** IPv6-incapable modes are skipped with English warnings

### Requirement: Netscan port probing SHALL be explicit and mode-gated
The system SHALL surface port findings only for modes that are explicitly port-relevant in this module (`T`, `TS`, `U`, `O`). It SHALL use `tcpPorts` for `T/TS`, `udpPorts` for `U`, and fixed endpoint logic for `O`, and SHALL include open-port results in normalized output.

#### Scenario: TCP mode uses configured TCP ports
- **WHEN** `scanMode` includes `T` or `TS` and `tcpPorts` is provided
- **THEN** probe attempts are limited to configured TCP ports

#### Scenario: UDP mode uses configured UDP ports
- **WHEN** `scanMode` includes `U` and `udpPorts` is provided
- **THEN** probe attempts are limited to configured UDP ports

#### Scenario: OXID mode uses fixed endpoint probe
- **WHEN** `scanMode` includes `O`
- **THEN** probe attempts include OXID-relevant TCP endpoint probing
- **AND** open TCP findings from `O` are allowed in normalized output

#### Scenario: ICMP/NetBIOS-only selection does not perform port probing
- **WHEN** selected modes are limited to non-port discovery modes (`ICP`, `ICA`, `ICT`, `N`)
- **THEN** no port probe is executed
- **AND** open-port fields in output remain empty

#### Scenario: A-only run does not emit port findings
- **WHEN** the user selects only `A`
- **THEN** output port fields (`openPorts`, `openTcpPorts`, `openUdpPorts`, `portScanModes`) remain null/empty
- **AND** no TCP/UDP port finding is surfaced from ARP compatibility fallback internals

### Requirement: Netscan probe provenance SHALL reflect effective execution path
The system SHALL report probe `sources` according to actual executed path, including fallback behavior.

#### Scenario: TS fallback reports effective source
- **WHEN** `TS` runs on a build/runtime where SYN falls back to TCP connect
- **THEN** row-level `sources` includes `tcp_connect`
- **AND** warnings indicate fallback behavior in English

### Requirement: Netscan runtime throttling MUST be adaptive and always enabled
The runtime MUST continuously adapt effective probe rate and concurrency using host resource pressure signals while honoring user-provided `pps` and `workers` as hard upper bounds.

#### Scenario: Runtime scales down under pressure
- **WHEN** CPU or memory pressure crosses configured high watermark during scan
- **THEN** effective probe rate and active workers are reduced automatically

#### Scenario: Runtime scales up when pressure is low and backlog remains
- **WHEN** resource pressure is low and unresolved targets remain
- **THEN** effective probe rate and active workers increase gradually
- **AND** neither value exceeds configured ceilings

#### Scenario: Adaptive throttling does not block successful completion
- **WHEN** scan backlog reaches zero under adaptive worker throttling
- **THEN** worker loops exit without requiring external cancellation
- **AND** command flow continues to output emission and normal process exit

### Requirement: Netscan CLI progress rendering SHALL keep progress row first
The CLI runtime SHALL render an initial netscan progress row before informational notices so progress remains pinned at the top during execution.

#### Scenario: No-target info prints below initialized progress row
- **WHEN** the user runs `c-eyes netscan` without `target` and `targetFile`
- **THEN** one progress frame is rendered first
- **AND** subsequent informational notices are printed below the progress row

### Requirement: Netscan SHALL persist deterministic asset identity and timeline locally
The system SHALL maintain a local persistent asset store to keep stable `assetId` and cross-run `firstSeen/lastSeen`. `assetId` generation SHALL be deterministic with MAC-first identity semantics: when a normalized MAC exists, `assetId` SHALL be derived from MAC alone; otherwise the runtime MAY fall back to an IP-only weak identity.

#### Scenario: Asset ID remains stable across runs
- **WHEN** the same normalized asset keys are observed in later scans
- **THEN** the returned `assetId` is identical across runs

#### Scenario: MAC-based identity remains stable across IP changes
- **WHEN** the same normalized MAC is observed in later scans with a different IP address
- **THEN** the returned `assetId` remains identical across runs

#### Scenario: firstSeen and lastSeen are updated correctly
- **WHEN** an existing asset is rediscovered
- **THEN** `firstSeen` remains unchanged
- **AND** `lastSeen` is updated to the current scan time

#### Scenario: IP-only weak identity can be upgraded to MAC identity when evidence agrees
- **WHEN** a persisted asset was previously stored using an IP-only weak identity
- **AND** a later scan observes the same IP with a normalized MAC
- **AND** available identity evidence such as hostname, OS family, or device type does not conflict
- **THEN** the runtime upgrades the persisted record to the MAC-based identity
- **AND** `firstSeen` is preserved during the upgrade

### Requirement: Netscan managed-source reconciliation SHALL classify assets deterministically
When `managedSource` is provided, the system SHALL load managed records from supported file formats and classify scanned assets with precedence `ip+mac` first, then `ip`, producing `managed/unmanaged` status deterministically.

#### Scenario: Managed match uses ip+mac precedence
- **WHEN** both IP and MAC are available and a matching managed record exists
- **THEN** classification uses the `ip+mac` match result as authoritative

#### Scenario: Managed fallback uses IP when MAC is unavailable
- **WHEN** MAC is unavailable or unmatched but IP matches a managed record
- **THEN** the asset is classified as `managed` by IP fallback

### Requirement: Netscan output SHALL use a normalized asset result schema
The system SHALL output a consistent result envelope containing `total` and `rows`, where each row includes asset identity, network attributes, status, timeline, probe provenance, and optional port findings.

#### Scenario: Result envelope fields are present
- **WHEN** netscan completes successfully
- **THEN** output includes `total` and `rows`

#### Scenario: Row-level fields include required identity and status
- **WHEN** any discovered asset is returned
- **THEN** each row includes `assetId`, `ipAddress`, `assetStatus`, and `lastSeen`
- **AND** row fields for optional values remain present with null or empty-list fallbacks as applicable

### Requirement: Netscan filter options SHALL be applied on normalized rows
The system SHALL apply `assetStatus` and `keyword` filters on normalized assets and SHALL support deterministic ordering by `sortBy` and `sortOrder`.

#### Scenario: Status and keyword filters combine as AND
- **WHEN** both `assetStatus` and `keyword` are provided
- **THEN** only rows satisfying both filters are returned

#### Scenario: Sorting is deterministic
- **WHEN** `sortBy` and `sortOrder` are provided
- **THEN** output rows are ordered deterministically according to requested field and direction

### Requirement: Netscan SHALL support opt-in routed reachable-segment discovery
The system SHALL provide a `reachableSegments` execute option for `netscan`. When enabled, the runtime SHALL discover candidate private routed segments from in-process local visibility sources and run bounded verification before marking segments as reachable.

#### Scenario: Reachable-segment discovery is disabled by default
- **WHEN** the user executes `c-eyes netscan` without `-reachableSegments`
- **THEN** routed reachable-segment discovery is not executed
- **AND** default target behavior remains primary-interface C-segment discovery when no explicit target is provided

#### Scenario: Reachable-segment discovery runs only when explicitly enabled
- **WHEN** the user executes `c-eyes netscan -reachableSegments`
- **THEN** the runtime collects candidate routed segments from local route visibility and local active connection evidence
- **AND** candidates are normalized and deduplicated before verification

#### Scenario: Candidate scope is limited to private network ranges
- **WHEN** reachable-segment discovery evaluates route and connection candidates
- **THEN** only RFC1918 IPv4 private segments are eligible for verification
- **AND** loopback, link-local, multicast, and default-route catch-all entries are excluded

### Requirement: Netscan reachable-segment verification SHALL be bounded and deterministic
The system SHALL verify routed segment candidates with a deterministic small probe plan and SHALL enforce existing safety boundaries for effective probing.

#### Scenario: Verification uses a bounded gateway-oriented probe plan
- **WHEN** a candidate routed segment is selected for verification
- **THEN** probe targets are limited to a deterministic gateway-oriented address set (including route next-hop when available)
- **AND** segment reachability is marked only when at least one verification probe succeeds

#### Scenario: Safety limits remain enforced with reachable-segment mode
- **WHEN** `reachableSegments` is enabled and additional probe targets are derived from verified segments
- **THEN** effective targets still obey `maxTargets` and adaptive runtime ceilings
- **AND** runtime emits explicit English warnings when candidates or probes are skipped due to bounds or capability limits

### Requirement: Netscan SHALL expose reachable-segment evidence in metrics output
When reachable-segment mode is enabled, the system SHALL report discovery and verification evidence in result metrics so operators can audit what was inferred and confirmed.

#### Scenario: Metrics include candidate and verified segment summaries
- **WHEN** `c-eyes netscan -reachableSegments` completes
- **THEN** output metrics include counts for discovered candidates and verified reachable segments
- **AND** output metrics include per-segment evidence fields with discovery source and verification method

#### Scenario: Partial collector availability is visible to users
- **WHEN** an OS-specific route or connection collector is unavailable or permission-limited
- **THEN** reachable-segment discovery continues with remaining available collectors
- **AND** output warnings include explicit English diagnostics for the unavailable collector path

### Requirement: Netscan default persistent store SHALL follow executable directory
The netscan runtime SHALL store its default persistent asset database next to the executable as `<exe-dir>/netscan-assets.db`. If the executable path cannot be resolved, the runtime MAY fall back to `./netscan-assets.db`.

#### Scenario: Default netscan asset database is created next to executable
- **WHEN** `netscan` initializes its default persistent asset store
- **THEN** the runtime uses `<exe-dir>/netscan-assets.db`

#### Scenario: Default netscan asset database falls back to current directory
- **WHEN** the runtime cannot resolve the executable path
- **THEN** the default persistent asset database path falls back to `./netscan-assets.db`
