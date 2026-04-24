## ADDED Requirements

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
