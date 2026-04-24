## ADDED Requirements

### Requirement: 智能子集预算 SHALL 根据候选总量动态计算
当本地文件扫描启用 `--smart` 时，系统 MUST 基于当前扫描范围候选总量动态计算智能子集预算，而非固定常量上限。

#### Scenario: Dynamic budget is derived from candidate volume
- **WHEN** the user executes `c-eyes filescan --scan-mode full --smart`
- **THEN** the system first computes candidate volume for the declared scope
- **AND** the smart subset budget is calculated from candidate volume using configured dynamic rules

#### Scenario: User max-targets remains a hard cap
- **WHEN** the user executes `c-eyes filescan --scan-mode path <path> --smart --max-targets <limit>`
- **THEN** the final selected target count MUST NOT exceed `<limit>`

## MODIFIED Requirements

### Requirement: CLI 支持文件扫描
系统 SHALL 在 `c-eyes filescan` 命令下提供本地文件扫描能力，支持 `--scan-mode` 本地扫描参数与 `--smart` 智能子集参数，并复用全局 `-o` 控制文件输出。

#### Scenario: 默认自动导出 Excel
- **WHEN** 用户执行 `c-eyes filescan --scan-mode full --smart` 且未提供 `-o`
- **THEN** 系统在当前目录自动导出 `result*.xlsx` 结果文件

#### Scenario: Excel 输出
- **WHEN** 用户执行 `c-eyes filescan --scan-mode path /tmp --smart -o out.xlsx`
- **THEN** 系统生成 Excel 文件并将结果写入该路径

#### Scenario: Path 模式参数校验
- **WHEN** 用户执行 `c-eyes filescan --scan-mode path` 但未提供 `<path>`
- **THEN** 系统返回中文错误并以非 0 退出

#### Scenario: 旧参数 --scan-path 被拒绝
- **WHEN** 用户执行 `c-eyes filescan --scan-mode path --scan-path /tmp`
- **THEN** 系统返回中文错误并提示改用 `--scan-mode path <path>`

### Requirement: 支持三种扫描模式
系统 SHALL 将本地文件扫描范围限制为 `full` 与 `path` 两种 `--scan-mode`；智能策略 SHALL 通过 `--smart` 参数启用，并在 `c-eyes filescan -h` 中给出模式与参数说明。

#### Scenario: 全盘扫描
- **WHEN** 用户执行 `c-eyes filescan --scan-mode full`
- **THEN** 系统扫描主机所有可用磁盘文件

#### Scenario: 指定路径扫描
- **WHEN** 用户执行 `c-eyes filescan --scan-mode path /tmp`
- **THEN** 系统仅扫描 `/tmp` 目录下的文件

#### Scenario: 全盘智能子集扫描
- **WHEN** 用户执行 `c-eyes filescan --scan-mode full --smart`
- **THEN** 系统在全盘候选中按高危/敏感规则筛选智能子集并执行扫描

#### Scenario: 旧 smart 模式参数被拒绝
- **WHEN** 用户执行 `c-eyes filescan --scan-mode smart`
- **THEN** 系统返回参数错误并提示 `--scan-mode` 仅支持 `full/path`

### Requirement: 智能扫描管线顺序
系统 MUST 在启用 `--smart` 时按 Target Collector -> Filter Engine -> Deep Scanner -> Result Reporter 顺序处理智能子集任务。

#### Scenario: 管线顺序执行
- **WHEN** Smart subset processing handles a single `ScanTask`
- **THEN** 任务依次经过目标收集、过滤、深度扫描与结果上报

### Requirement: 输出字段与结果格式
系统 SHALL 以 JSON/CSV/Excel 输出统一结构，包含扫描元信息与扩展采集字段：

- 顶层扫描元信息：`scan_mode`, `smart_enabled`, `source`, `hostname`, `displayIp`, `externalIpList`, `internalIpList`。
- `basic_info`：`file_path`, `file_name`, `file_size_bytes`, `creation_time`, `modification_time`, `access_time`（RFC3339，毫秒精度），以及平台差异字段（Windows: `attributes`；Linux: `owner`, `group`, `mode`）。
- `hashes`：`sha256`, `imphash`。
- `signature`（Windows 可用）：`is_signed`, `signature_valid`, `signer_subject`, `certificate_thumbprint`。
- `binary_info`（仅 PE/ELF 可执行文件）：`magic_bytes`, `imported_libraries`, `sections_info`, `version_info`。
- `context`（Windows 可用）：`motw_zone_id`, `download_url`。

Excel 输出 SHALL 采用扁平化列名 `group.field`（如 `basic_info.file_path`、`hashes.sha256`、`signature.is_signed`），数组/对象字段（如 `imported_libraries`, `sections_info`, `version_info`）在 Excel 中以 JSON 字符串形式输出。

#### Scenario: 字段缺失处理
- **WHEN** 某字段不可获取或不适用（例如非 PE/ELF 文件）
- **THEN** 对应字段在 JSON 中输出为 `null`；`externalIpList/internalIpList` 在无数据时输出空数组

#### Scenario: Smart flag output reflects runtime strategy
- **WHEN** 用户执行 `c-eyes filescan --scan-mode path /tmp --smart`
- **THEN** 每条输出记录中的 `smart_enabled` 为 `true`
- **AND** `scan_mode` 仍为 `path`

### Requirement: Local file-scan pipeline SHALL use mode-aware adaptive worker profiles
The local file-scan pipeline MUST derive worker profile bounds from scan mode, smart flag state, task volume, and host capacity, then tune active workers dynamically during execution.

#### Scenario: Smart-enabled local runs use bounded adaptive workers
- **WHEN** local pipeline initializes profile for a large task volume under `--scan-mode full --smart`
- **THEN** the smart-enabled profile selects bounded initial/max workers suitable for subset scanning
- **AND** active workers remain within profile min/max bounds

#### Scenario: Adaptive tuning periodically adjusts active local workers
- **WHEN** local pipeline is running and adaptive mode is enabled
- **THEN** runtime periodically re-evaluates CPU utilization, memory pressure, and remaining backlog
- **AND** active workers are adjusted within profile min/max bounds

#### Scenario: Memory pressure clamps local worker ceiling
- **WHEN** runtime memory usage crosses high-pressure threshold
- **THEN** local pipeline reduces active workers and prevents growth above pressure-adjusted limits until pressure drops

### Requirement: Windows drive-root path scope SHALL be interpreted as a valid local smart boundary
For `--scan-mode path <path> --smart`, when `<path>` is a Windows drive root (for example `D:\`), the scope matcher MUST treat all descendants on that drive as in-scope and MUST keep other drives out of scope.

#### Scenario: Drive-root scope matching keeps same-drive descendants
- **WHEN** the user executes `c-eyes filescan --scan-mode path D:\\ --smart`
- **THEN** candidates under `D:\...` are eligible for smart subset selection
- **AND** candidates under `E:\...` are rejected as out-of-scope
