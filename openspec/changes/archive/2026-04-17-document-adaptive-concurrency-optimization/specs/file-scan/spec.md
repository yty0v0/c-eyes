## ADDED Requirements

### Requirement: Local file-scan pipeline SHALL use mode-aware adaptive worker profiles
The local file-scan pipeline MUST derive worker profile bounds from scan mode, task volume, and host capacity, then tune active workers dynamically during execution.

#### Scenario: Path/full modes allow higher default worker ceiling than smart mode
- **WHEN** local pipeline initializes profile for the same large task volume in `path` (or `full`) and `smart` modes
- **THEN** `path/full` profile uses worker ceiling greater than or equal to the `smart` profile ceiling
- **AND** `path/full` profile initial workers are greater than or equal to `smart` profile initial workers

#### Scenario: Adaptive tuning periodically adjusts active local workers
- **WHEN** local pipeline is running and adaptive mode is enabled
- **THEN** runtime periodically re-evaluates CPU utilization, memory pressure, and remaining backlog
- **AND** active workers are adjusted within profile min/max bounds

#### Scenario: Memory pressure clamps local worker ceiling
- **WHEN** runtime memory usage crosses high-pressure threshold
- **THEN** local pipeline reduces active workers and prevents growth above pressure-adjusted limits until pressure drops

### Requirement: Local file-scan optimization SHALL preserve result-set contract
Adaptive concurrency and performance tuning MUST NOT intentionally change the result-set contract for the same static input snapshot.

#### Scenario: Static dataset preserves record keyset across adaptive profiles
- **WHEN** the same static directory snapshot is scanned multiple times with different adaptive worker profiles
- **THEN** the resulting record keyset remains equivalent for contract fields (for example target path plus stable file hash)
