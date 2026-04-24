# Filescan

## Purpose

定义 `c-eyes filescan` 聚合入口�?Web 子模块与本地文件模式下的选择规则、参数约束、去重策略与串联风险分析契约�?
## Requirements
### Requirement: filescan 提供统一文件扫描入口
系统 SHALL 提供 `c-eyes filescan` 作为文件信息扫描统一入口，支�?`--custom` �?`--all` 选择 `site/framework/jarpackage` 子模块；当未显式提供模块选择时默认执�?`all`�?
#### Scenario: 默认执行 web 子模�?all 扫描
- **WHEN** 用户执行 `c-eyes filescan` 且未提供 `--custom/--all`
- **THEN** 系统默认执行 `site/framework/jarpackage` 全部子模块并输出聚合结果

#### Scenario: 自定义多模块扫描
- **WHEN** 用户执行 `c-eyes filescan --custom site,framework`
- **THEN** 系统仅执�?site �?framework 两个子模块并输出合并结果

#### Scenario: custom �?all 同时出现
- **WHEN** 用户执行 `c-eyes filescan --custom site --all`
- **THEN** 系统返回中文参数冲突错误并以�?0 退�?

### Requirement: filescan 支持本地文件扫描模式且与 web 子模块互�?系统 SHALL �?`filescan` 中支持本地文件扫描模�?`full/path/smart`（默�?`smart`），并且本地文件模式�?`site/framework/jarpackage` 选择 MUST 互斥�?
#### Scenario: 本地 smart 扫描并串联风险分�?- **WHEN** 用户执行 `c-eyes filescan --scan-mode smart -r`
- **THEN** 系统执行本地文件 smart 扫描并进入风险分析流�?
#### Scenario: web 子模块与本地模式混用
- **WHEN** 用户执行 `c-eyes filescan --custom site --scan-mode smart`
- **THEN** 系统返回中文错误，提示两类模式不能同时启�?

### Requirement: filescan 聚合参数与去重规�?�?`site/framework/jarpackage` 多模块或 all 场景下，系统 SHALL 仅接受子模块参数交集，并对输出结果按“完全一致记录”去重�?
#### Scenario: web 聚合使用非交集参�?- **WHEN** 用户�?`c-eyes filescan --all` 请求中提供非交集参数
- **THEN** 系统返回中文参数错误并拒绝执�?
#### Scenario: web 聚合去重
- **WHEN** 两个子模块产生字段和值完全一致的记录
- **THEN** 输出中仅保留一条记�?

### Requirement: filescan 串联风险分析仅输出分析结�?当用户在 `filescan` 命令上启�?`-r/--riskanalyze` 时，系统 SHALL 在扫描完成后执行风险分析，并且仅输出分析结果�?
#### Scenario: filescan 默认风险模式
- **WHEN** 用户执行 `c-eyes filescan -r` 且未提供风险模式
- **THEN** 系统�?`smart` 作为默认风险分析模式

#### Scenario: filescan -r 输出行为
- **WHEN** 用户执行任意 `filescan` + `-r` 组合
- **THEN** 系统只输出风险分析结果，不输出扫描结�?

### Requirement: filescan 本地扫描在异常二进制样本上保持稳�?系统 MUST 在本地文件扫描与串联风险分析中，对异常或损坏�?PE 导入表解析进行容错处理，避免进程级崩溃�?
#### Scenario: 智能扫描遇到异常 PE 样本
- **WHEN** 用户执行 `c-eyes filescan --scan-mode smart -r`，目标集中包含导入表损坏�?PE 文件
- **THEN** 系统跳过异常字段并继续处理其余记录，不发�?panic

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

### Requirement: Filescan risk help SHALL include risk-usable parameter categories
Filescan help SHALL consolidate risk-parameter guidance into `c-eyes filescan -h`, and `c-eyes filescan -r -h` SHALL no longer require a separate dedicated risk-help page.

#### Scenario: Risk parameters are visible in filescan help page
- **WHEN** the user executes `c-eyes filescan -h`
- **THEN** the output includes an `OPTIONS(only -r enable can use)` section
- **AND** that section includes `-yara-rules`, `-analysis-max-duration`, `-cloud-upload`, and `--risk-mode`

#### Scenario: Filescan risk-help entry reuses consolidated page
- **WHEN** the user executes `c-eyes filescan -r -h`
- **THEN** the command shows the consolidated filescan help content instead of a separate risk-only help page

### Requirement: Filescan custom module help SHALL support single and multi-module inspection
For `c-eyes filescan --custom <modules> -h`, the help output SHALL be module-scoped and MUST present only the relevant `OPTIONS` section for the selected module set, including `software`.

#### Scenario: Single custom software module help shows only software options
- **WHEN** the user executes `c-eyes filescan --custom software -h`
- **THEN** the help output shows only the `OPTIONS` section for `software` module filtering parameters

#### Scenario: Multi custom module help with software shows intersection options
- **WHEN** the user executes `c-eyes filescan --custom site,software -h`
- **THEN** the help output shows only the `OPTIONS` section for the selected modules' common parameter intersection

### Requirement: Filescan web-module routing SHALL execute software module paths
For non-local filescan execution, the system SHALL recognize `software` as a valid web-mode module in `--custom` and `--all` routes.

#### Scenario: Filescan custom software dispatch
- **WHEN** the user executes `c-eyes filescan --custom software`
- **THEN** the command dispatches only the software collector path and returns software rows in unified scan output

#### Scenario: Filescan all-mode includes software dispatch
- **WHEN** the user executes `c-eyes filescan --all`
- **THEN** the command dispatches `software` together with all other filescan web modules and returns merged deduplicated rows

### Requirement: Filescan local mode SHALL remain mutually exclusive with software web-mode
The system MUST keep `--scan-mode` mutually exclusive with all web modules, including `software`.

#### Scenario: Local mode mixed with software module is rejected
- **WHEN** the user executes `c-eyes filescan --custom software --scan-mode path <path> --smart`
- **THEN** the command returns an argument conflict error indicating local scan mode cannot be used with web-module selection

### Requirement: Filescan chained risk mapping SHALL include software path candidates
When `filescan -r` runs with software rows, the system SHALL map software records to risk scan records using file target candidates from `binPath` and `configPath`.

#### Scenario: Software row creates risk records from bin and config paths
- **WHEN** a software row contains `binPath` and/or `configPath` during `c-eyes filescan --custom software -r`
- **THEN** the chained risk input includes candidate `target_path` values derived from those fields with deduplicated paths

#### Scenario: Filescan risk output behavior remains risk-only for software runs
- **WHEN** the user executes `c-eyes filescan --custom software -r`
- **THEN** the command outputs risk-analysis results only and does not emit raw software scan rows

### Requirement: Filescan multi-module intersection SHALL remain stable when software participates
In multi-module web-mode runs that include `software`, the system SHALL keep intersection-only argument behavior (`groups`, `hostname`, `ip`) for shared filtering.

#### Scenario: Non-intersection argument is rejected in software multi-module mode
- **WHEN** the user executes `c-eyes filescan --custom site,software -name nginx`
- **THEN** the command returns an argument error indicating multi-module mode only supports intersection filters

### Requirement: Filescan runtime SHALL require explicit execution mode
For non-help execution, unified filescan SHALL require one of `--all`, `--custom`, or `--scan-mode`.

#### Scenario: Filescan rejects missing execution mode flags
- **WHEN** the user executes `c-eyes filescan` without `--all`, `--custom`, and `--scan-mode`
- **THEN** the command returns an argument error indicating filescan requires one of `--all`, `--custom`, or `--scan-mode`

### Requirement: Filescan unified execution SHALL display terminal progress
During unified filescan execution (Web module mode and local scan-mode), progress rows SHALL be shown in terminal output.

#### Scenario: Filescan local path scan prints progress rows
- **WHEN** the user executes `c-eyes filescan --scan-mode path <path>`
- **THEN** stderr includes progress rows labeled `filescan` with `done/total` counters
- **AND** progress stage includes local-mode scope such as `scan-mode=path | <stage>`

### Requirement: Filescan web-module execution SHALL use adaptive module concurrency
For multi-module web-mode filescan execution, the system SHALL run module collectors with bounded adaptive concurrency using runtime pressure and backlog signals.

#### Scenario: Filescan all web modules execute with bounded adaptive concurrency
- **WHEN** the user executes `c-eyes filescan --all`
- **THEN** module collectors run concurrently with active workers between configured minimum and maximum bounds
- **AND** active workers never exceed selected web-module count

#### Scenario: Filescan web adaptive scheduler reacts to pressure and backlog
- **WHEN** runtime CPU/memory pressure is high during web-mode module execution
- **THEN** active module concurrency is reduced toward minimum bound
- **AND** when pressure is low with remaining backlog, active module concurrency is increased toward maximum bound

### Requirement: Filescan local mode SHALL reject manual workers flag
Local filescan runtime concurrency MUST be managed automatically, and manual `--workers` input SHALL be rejected.

#### Scenario: Local filescan rejects --workers flag
- **WHEN** the user executes `c-eyes filescan --scan-mode path <path> --smart --workers 4`
- **THEN** the command returns an argument error indicating `--workers` is not supported

#### Scenario: Local filescan keeps automatic concurrency when workers flag is absent
- **WHEN** the user executes `c-eyes filescan --scan-mode full --smart` without `--workers`
- **THEN** local scan starts with runtime-selected adaptive concurrency behavior

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

### Requirement: Filescan local path mode SHALL return explicit access-denied root errors
For `--scan-mode path <path>`, if the declared root path cannot be enumerated due to permissions, filescan MUST fail with a clear access-denied path error.

#### Scenario: Path root access denied
- **WHEN** a user executes `c-eyes filescan --scan-mode path <path>` and `<path>` is not listable by current user
- **THEN** filescan exits with a path-scoped access-denied error
- **AND** the message references the denied scan path

### Requirement: Filescan local collection SHALL report inaccessible entries and continue
During local collection in `full` or `path` scope, walker-level permission failures MUST be reported per inaccessible entry and MUST NOT abort the whole run.

#### Scenario: Multiple denied entries in one scan scope
- **WHEN** collection traverses a scope that contains multiple inaccessible files/directories
- **THEN** filescan prints one warning per denied entry encountered by the collector
- **AND** scanning continues for remaining accessible targets

#### Scenario: Denied directory does not produce synthetic child warnings
- **WHEN** a directory entry itself is inaccessible to traversal
- **THEN** filescan reports that denied entry
- **AND** filescan does not emit fabricated warnings for unknown descendants under that denied directory

### Requirement: Filescan chained risk SHALL keep phase-separated progress behavior
In `filescan -r` mode, filescan phase and risk phase progress MUST remain phase-separated and readable.

#### Scenario: Filescan and risk progress rows remain sequentially readable
- **WHEN** a user executes `c-eyes filescan ... -r`
- **THEN** filescan progress completes first
- **AND** risk progress runs as a single active row during risk phase without spawning parallel duplicate rows

