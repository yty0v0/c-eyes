## Why

The current unified EDR CLI has no SBOM collection module, so users cannot produce standardized software bill-of-materials output from the same command surface as `hostscan/filescan/eventlog/netscan`. We need to add a collection-only SBOM module now to support software inventory workflows with consistent CLI behavior, cross-platform execution, and standardized JSON output.

## What Changes

- Add a new top-level `sbom` command aligned with existing unified modules (`hostscan`, `filescan`, `eventlog`, `netscan`).
- Integrate the local SBOM implementation from `C:\Users\Administrator\Desktop\sbom` as an internal module in this repository.
- Keep SBOM as collection-only mode (no risk-analysis chaining, no `-r/--riskanalyze` support on `sbom`).
- Require explicit `-p/--path` for SBOM scan scope (no implicit current-directory default).
- Reuse global `-o/--output` for SBOM output path control; do not add `-p/--path` output flag.
- Define SBOM-specific default output behavior when `-o` is omitted: auto-generate `result*.json` in current working directory.
- Restrict SBOM output file type to `.json`, and support SBOM content format selection via SBOM command option (`xspdx-json` default, `spdx-json` optional).
- Ensure CLI prompts/help/error messages for SBOM are English and UTF-8 compatible.
- Normalize `docs/sbom.md` to UTF-8 and update requirement wording to match final decisions.

## Capabilities

### New Capabilities
- `sbom-scan`: Collect SBOM data on Windows/Linux and emit standards-based JSON output through the unified `c-eyes sbom` command.

### Modified Capabilities
- `global-output`: Add SBOM-specific default output auto-naming (`result*.json`) and enforce SBOM `.json` output constraint while keeping global `-o` contract.
- `cli-help-prompts`: Include `sbom` in root/subcommand help and define SBOM-specific help/usage/error prompt expectations.

## Impact

- Affected code:
  - Unified CLI command routing/parsing/output path resolution in `cmd/edr`.
  - New internal SBOM package integration under `internal/` and adapters for module execution/output.
  - Output writers/validators for SBOM JSON behavior.
  - Documentation updates for SBOM usage and output semantics.
- Affected behavior:
  - New user-facing command `c-eyes sbom`.
  - SBOM command uses global `-o` but has module-specific default output and suffix constraints.
- Dependencies:
  - Additional Go dependencies required by the integrated SBOM module (as needed by imported implementation).
