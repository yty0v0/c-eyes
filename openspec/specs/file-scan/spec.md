# File Scan

## Purpose

定义文件扫描能力的命令接口、扫描模式、智能扫描流程与输出契约，确保 c-eyes file scan 在跨平台环境下以一致结构输出结果，并支持 JSON 与 Excel 两种交付形式。
## Requirements
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
系统 MUST 按 Target Collector -> Filter Engine -> Deep Scanner -> Result Reporter 顺序处理智能扫描任务。

#### Scenario: 管线顺序执行
- **WHEN** Smart Scan 处理单个 ScanTask
- **THEN** 任务依次经过目标收集、过滤、深度扫描与结果上报

### Requirement: Target Collector 覆盖高危来源
系统 SHALL 从以下来源收集待扫描目标，且不遍历完整文件树：
活跃进程可执行文件与已加载模块；持久化项（Run/RunOnce、服务、计划任务、启动文件夹）；高危落脚点目录（%USERPROFILE%\\Downloads、%TEMP%、AppData、回收站）；过去 24 小时内新建或修改的 PE/脚本文件。

#### Scenario: 近期变动文件
- **WHEN** Smart Scan 启动
- **THEN** 系统通过 USN Journal 或 inotify 获取过去 24 小时内变动的 PE/脚本文件

### Requirement: 过滤引擎按短路顺序执行
系统 MUST 按以下顺序短路执行过滤：本地缓存比对 -> 信任签名校验 -> 云端信誉查杀。

#### Scenario: 本地缓存命中
- **WHEN** 缓存中存在且 `file_path` 与 `last_modified` 匹配
- **THEN** 直接复用历史结果并跳过后续步骤

#### Scenario: 信任签名命中
- **WHEN** 文件签名发布者受信任
- **THEN** 标记为 `SAFE` 并写入缓存

#### Scenario: 云端信誉黑名单
- **WHEN** 云端信誉返回黑名单
- **THEN** 系统输出 `MALICIOUS` 并告警

#### Scenario: 云端信誉白名单
- **WHEN** 云端信誉返回白名单
- **THEN** 系统输出 `SAFE` 并写入缓存

#### Scenario: 云端信誉未知
- **WHEN** 云端信誉返回未知
- **THEN** 文件进入深度扫描流程

### Requirement: 深度扫描仅处理灰文件
系统 SHALL 仅对过滤后仍为 `UNKNOWN` 的文件执行深度扫描，并调用 YARA 或等效引擎。

#### Scenario: 深度扫描触发
- **WHEN** 文件经缓存/签名/信誉过滤后结果为 `UNKNOWN`
- **THEN** 系统调用深度扫描引擎进行检测

### Requirement: 深度扫描资源限制
系统 MUST 在低优先级线程运行深度扫描，并进行 I/O 限流。

#### Scenario: Windows 线程优先级
- **WHEN** 在 Windows 运行深度扫描
- **THEN** 系统将线程优先级设置为最低并限制磁盘 I/O

### Requirement: ScanCache 数据模型
系统 SHALL 使用本地 SQLite 维护 `ScanCache` 表，包含 `file_path`, `file_hash`, `last_modified`, `scan_result`, `last_scan_time` 字段。

#### Scenario: 缓存写入
- **WHEN** 完成一次扫描并得到结果
- **THEN** 系统写入或更新 `ScanCache` 记录

### Requirement: 智能扫描触发机制
系统 SHALL 支持系统空闲触发与行为驱动触发。

#### Scenario: 系统空闲触发
- **WHEN** CPU 空闲且无用户输入超过 5-10 分钟
- **THEN** 系统启动或恢复智能扫描

#### Scenario: 用户恢复活动
- **WHEN** 监测到用户输入恢复
- **THEN** 系统调用 `Pause()` 暂停扫描线程

#### Scenario: 行为驱动触发
- **WHEN** 本地 RPC/接口收到驱动推送的高危文件事件
- **THEN** 系统将该文件作为 `ScanTask` 立即扫描

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

#### Scenario: Excel 数组/对象字段序列化
- **WHEN** `binary_info.imported_libraries` 或 `binary_info.sections_info` 为数组/对象
- **THEN** Excel 单元格中输出其 JSON 字符串序列化结果

### Requirement: 文件扫描输出主机 IP 列表字段
系统 SHALL 在文件扫描结果中输出主机维度字段 `displayIp`、`internalIpList`、`externalIpList`。

#### Scenario: 文件扫描主机字段
- **WHEN** 用户执行任意文件扫描模式
- **THEN** 每条结果记录包含主机 IP 列表字段

#### Scenario: Excel 导出包含列表列
- **WHEN** 用户使用文件扫描 Excel 导出
- **THEN** 导出列中包含 `internalIpList` 与 `externalIpList`

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

### Requirement: Local file-scan optimization SHALL preserve result-set contract
Adaptive concurrency and performance tuning MUST NOT intentionally change the result-set contract for the same static input snapshot.

#### Scenario: Static dataset preserves record keyset across adaptive profiles
- **WHEN** the same static directory snapshot is scanned multiple times with different adaptive worker profiles
- **THEN** the resulting record keyset remains equivalent for contract fields (for example target path plus stable file hash)

### Requirement: 智能子集预算 SHALL 根据候选总量动态计算
当本地文件扫描启用 `--smart` 时，系统 MUST 基于当前扫描范围候选总量动态计算智能子集预算，而非固定常量上限。

#### Scenario: Dynamic budget is derived from candidate volume
- **WHEN** the user executes `c-eyes filescan --scan-mode full --smart`
- **THEN** the system first computes candidate volume for the declared scope
- **AND** the smart subset budget is calculated from candidate volume using configured dynamic rules

#### Scenario: User max-targets remains a hard cap
- **WHEN** the user executes `c-eyes filescan --scan-mode path <path> --smart --max-targets <limit>`
- **THEN** the final selected target count MUST NOT exceed `<limit>`

### Requirement: Windows drive-root path scope SHALL be interpreted as a valid local smart boundary
For `--scan-mode path <path> --smart`, when `<path>` is a Windows drive root (for example `D:\`), the scope matcher MUST treat all descendants on that drive as in-scope and MUST keep other drives out of scope.

#### Scenario: Drive-root scope matching keeps same-drive descendants
- **WHEN** the user executes `c-eyes filescan --scan-mode path D:\\ --smart`
- **THEN** candidates under `D:\...` are eligible for smart subset selection
- **AND** candidates under `E:\...` are rejected as out-of-scope

### Requirement: Path-mode collection MUST pre-check directory readability
Before walking `ScanModePath` roots, local file collection MUST verify root readability for directory paths and MUST fail early on permission denial.

#### Scenario: Directory root fails readability probe
- **WHEN** local path scan targets a directory root that exists but is not readable
- **THEN** collection fails early with an access-denied error for that root
- **AND** the run does not silently downgrade to "no targets found"

#### Scenario: File root bypasses directory-read probe
- **WHEN** local path scan target is a single file path
- **THEN** collection does not require directory-read probing
- **AND** the file remains eligible for scanning

### Requirement: Collector walker MUST surface entry-level permission errors via task callback
The local collector walker MUST surface permission and metadata-read failures through task-scoped error callbacks so callers can print per-entry diagnostics.

#### Scenario: Walk callback emits two denied entry errors
- **WHEN** walker encounters two separate inaccessible entries in one traversal
- **THEN** callback is invoked twice with stage `collect_targets`
- **AND** each callback includes the denied entry path and associated error

