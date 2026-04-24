## ADDED Requirements

### Requirement: Filescan local smart flag SHALL only be valid with full/path scan mode
For unified filescan local execution, `--smart` MUST be accepted only when `--scan-mode` is explicitly set to `full` or `path`.

#### Scenario: Smart flag without scan-mode is rejected
- **WHEN** the user executes `c-eyes filescan --smart`
- **THEN** the command returns an argument error indicating `--smart` requires `--scan-mode full|path`

#### Scenario: Smart flag with web-module mode is rejected
- **WHEN** the user executes `c-eyes filescan --all --smart`
- **THEN** the command returns an argument error indicating `--smart` cannot be used with web-module selection

#### Scenario: Legacy smart scan-mode is rejected
- **WHEN** the user executes `c-eyes filescan --scan-mode smart`
- **THEN** the command returns an argument error indicating `--scan-mode` only supports `full/path`

### Requirement: Filescan smart subset SHALL stay within declared local scope
When `--smart` is enabled, filescan MUST select only a high-risk/sensitive subset from the declared local scope, and MUST NOT expand scan targets outside that scope.

#### Scenario: Path smart scan stays in provided path
- **WHEN** the user executes `c-eyes filescan --scan-mode path <path> --smart`
- **THEN** all selected scan targets remain within `<path>` descendants
- **AND** no global fallback directories are added outside `<path>`

#### Scenario: Windows drive-root smart path scan keeps descendants in scope
- **GIVEN** `<path>` is a Windows drive root such as `D:\`
- **WHEN** the user executes `c-eyes filescan --scan-mode path D:\\ --smart`
- **THEN** targets under `D:\<subdir>\...` are treated as in-scope descendants
- **AND** targets under other drives (for example `E:\...`) are out of scope

## MODIFIED Requirements

### Requirement: Filescan help SHALL be grouped by usable mode and parameters
`c-eyes filescan -h` SHALL present English option-oriented help with `NAME`, `USAGE`, and `OPTIONS`.  
The options SHALL include Web module selection (`--custom site/framework/jarpackage/software`, `--all`) and local scan-mode usage (`--scan-mode full/path`) plus smart strategy toggle (`--smart`) with explicit guidance that:
- `--custom`, `--all`, and `--scan-mode` are mutually exclusive;
- `--smart` is usable only with `--scan-mode full|path`.

#### Scenario: Filescan base help shows smart flag with scope constraints
- **WHEN** the user executes `c-eyes filescan -h`
- **THEN** the output is shown in English with `NAME`, `USAGE`, and `OPTIONS`
- **AND** the `OPTIONS` section documents `--scan-mode full/path` and `--smart`
- **AND** the help text explicitly states `--smart` can only be used with `--scan-mode full|path`

#### Scenario: Smart option line is aligned and includes inline condition note
- **WHEN** the user executes `c-eyes filescan -h`
- **THEN** the `OPTIONS` section contains a dedicated `--smart` line aligned with peer options
- **AND** the line describes its purpose as smart subset scanning
- **AND** the same line includes a parenthesized usage condition such as `(only valid with --scan-mode full|path)`

### Requirement: Filescan local mode SHALL remain mutually exclusive with software web-mode
The system MUST keep `--scan-mode` mutually exclusive with all web modules, including `software`.

#### Scenario: Local mode mixed with software module is rejected
- **WHEN** the user executes `c-eyes filescan --custom software --scan-mode path <path> --smart`
- **THEN** the command returns an argument conflict error indicating local scan mode cannot be used with web-module selection

### Requirement: Filescan local mode SHALL reject manual workers flag
Local filescan runtime concurrency MUST be managed automatically, and manual `--workers` input SHALL be rejected.

#### Scenario: Local filescan rejects --workers flag
- **WHEN** the user executes `c-eyes filescan --scan-mode path <path> --smart --workers 4`
- **THEN** the command returns an argument error indicating `--workers` is not supported

#### Scenario: Local filescan keeps automatic concurrency when workers flag is absent
- **WHEN** the user executes `c-eyes filescan --scan-mode full --smart` without `--workers`
- **THEN** local scan starts with runtime-selected adaptive concurrency behavior
