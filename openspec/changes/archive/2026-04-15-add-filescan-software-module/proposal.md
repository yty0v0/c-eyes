## Why

Current `edr filescan` web-mode only covers `site`, `framework`, and `jarpackage`, so there is no unified way to collect software application inventory with the same cross-platform, non-command, and chained-risk workflow conventions. We need this now to close a practical inventory gap while keeping behavior aligned with existing filescan module contracts.

## What Changes

- Add a new `software` module under `edr filescan` for Windows/Linux software application information collection.
- Include `software` in `edr filescan --all` and `--custom` module selection behavior.
- Introduce module-level request filters for software records: `groups`, `hostname`, `ip`, `name`, `version`, `binPath`, `configPath`.
- Define normalized software output contract with host metadata, software metadata, and associated process list.
- Use list-based IP fields for software records (`externalIpList`, `internalIpList`) and remove single external/internal IP scalar modeling for this capability.
- Keep collection scope as metadata inventory only; no risk scoring fields in scan output.
- Align chained risk behavior for `filescan -r` by providing candidate `target_path` values from `binPath` and `configPath`.
- Extend filescan help/module option prompts in English to include `software` and its filter flags.

## Capabilities

### New Capabilities
- `software-scan`: Collect and normalize software application metadata on Windows and Linux using in-process OS/file/runtime sources (no external command execution), support filtering and JSON/Excel export.

### Modified Capabilities
- `filescan`: Extend unified filescan web-module selection, `--all` coverage, module-scoped help options, and chained-risk record mapping to include the new `software` module.

## Impact

- Affected specs: new `software-scan`; updated `filescan`.
- Affected CLI: unified filescan module parsing/help, module dispatch, and custom-option catalog updates.
- Affected scanning code: new internal software collection/filter/normalization package and tests for Windows/Linux behavior.
- Affected export/output: JSON/Excel column mapping for software records.
- Affected risk chain: `filescan -r` record mapping for software path candidates (`binPath`, `configPath`).
