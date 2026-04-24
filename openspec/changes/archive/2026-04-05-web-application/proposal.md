## Why

Current EDR coverage needs a standardized way to collect web application inventory and plugin metadata across Windows and Linux endpoints. We need this now to support consistent asset visibility and export workflows without coupling data collection to risk analysis.

## What Changes

- Add a new CLI capability to collect web application metadata from endpoints without invoking external shell commands for collection.
- Define optional query filters for business group, host identity, application identity, web root, server type, and domain.
- Define a normalized output contract for host/application/plugin fields, including list-based internal/external IPs.
- Support both JSON and Excel output formats for the same result schema.
- Explicitly constrain this capability to information collection only (no risk scoring or threat verdicts).

## Capabilities

### New Capabilities
- `web-application-scan`: Collect and normalize web application and plugin metadata across Windows/Linux with query filters and JSON/Excel output.

### Modified Capabilities
- None.

## Impact

- New OpenSpec capability under `openspec/changes/web-application/specs/web-application-scan/spec.md`.
- CLI command surface will expand with a new `edr web-application-scan` command and related filter/output flags.
- Data collection modules for Windows and Linux web application discovery will be added or extended.
- Output serialization/export layer will include JSON and Excel support for this dataset.
