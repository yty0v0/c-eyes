## Why

EDR investigations need consistent visibility into scheduled task persistence across Windows and Linux, but this data is currently fragmented and difficult to export in analyst-friendly formats. We need a dedicated, cross-platform collection capability now to support standardized endpoint inventory and downstream analysis pipelines.

## What Changes

- Add a cross-platform scheduled task collection capability for Windows and Linux that gathers task metadata without performing risk analysis.
- Add filterable query inputs for business group, host identity, user, execution path, config file path, task time range, and task type.
- Add normalized output records with task and host fields, including support for multiple internal/external IP values.
- Add CLI output in both JSON and Excel formats.
- Restrict task type classification to `CRONTAB`, `AT`, and `BATCH`.

## Capabilities

### New Capabilities
- `scheduled-task-scan`: Collect scheduled task metadata from Windows and Linux endpoints through OS APIs/libraries, and expose filtered export through CLI in JSON and Excel.

### Modified Capabilities
- None.

## Impact

- Affected code: scanner collection layer, cross-platform adapters, result normalization models, export format writers, and CLI parameter parsing.
- Affected APIs: CLI contract for request filters and output format selection.
- Dependencies: Excel writing library for Go (for `.xlsx` export) and existing endpoint metadata models.
- Systems: endpoint task inventory pipeline and analyst reporting workflows.
