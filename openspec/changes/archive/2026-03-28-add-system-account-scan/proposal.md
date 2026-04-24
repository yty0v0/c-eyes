## Why

Current EDR capabilities cover process and file collection, but there is no normalized system account inventory output aligned with the required API-style schema in `docs/system-account.md`. We need this now to support host account visibility and query filtering without invoking shell commands, while keeping collection-only scope separated from risk analysis.

## What Changes

- Add a new system account scan capability that collects account metadata on Linux and Windows using native file parsing and OS APIs (no command-line execution).
- Add request-parameter filtering aligned to the documented fields: groups, hostname, ip, status, name, home, lastLoginTime, gid, and uid.
- Add normalized JSON output as an object containing `total` and `rows`, with row fields matching the documented response contract.
- Add cross-platform field behavior where unsupported OS-specific fields are returned as null/empty values without failing the scan.
- Add CLI entrypoint support for account scanning and optional structured output reuse patterns used by existing scans.
- Add tests for parser correctness, filter behavior, and output schema mapping.

## Capabilities

### New Capabilities
- `system-account-scan`: Collect and query host system account information with a normalized cross-platform output contract.

### Modified Capabilities
- None.

## Impact

- Affected code: new `internal/accountscan` module, CLI command wiring in `cmd/edr`, and optional shared host metadata reuse.
- Affected APIs: introduces `edr account scan` output contract (`total` + `rows`) and filter flags.
- Dependencies/systems: Linux account files (`/etc/passwd`, `/etc/group`, `/etc/shadow`, login records) and Windows account APIs; no new external service dependency required.
