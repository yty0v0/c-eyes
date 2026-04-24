## ADDED Requirements

### Requirement: Netscan help SHALL document reachable-segment execute option behavior
The system SHALL document the `-reachableSegments` execute option in `netscan` help, including that it is opt-in and focused on routed reachable-segment discovery.

#### Scenario: Netscan help includes reachable-segment option in execute section
- **WHEN** the user executes `c-eyes netscan -h`
- **THEN** `EXECUTE OPTIONS` includes `-reachableSegments`
- **AND** the option description states that routed reachable-segment discovery is enabled only when this option is set

#### Scenario: Netscan help clarifies bounded behavior for reachable-segment mode
- **WHEN** the user executes `c-eyes netscan -h`
- **THEN** help text explains that reachable-segment discovery remains bounded by existing scan safety controls
- **AND** users are directed to use explicit targets when they need strict scan scope control
