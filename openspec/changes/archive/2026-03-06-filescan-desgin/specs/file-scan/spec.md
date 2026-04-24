## ADDED Requirements

### Requirement: CLI 支持文件扫描
系统 SHALL 提供 `edr file scan` 命令，支持 `--mode`、`--path`、`--excel` 参数，并返回标准化扫描结果。

#### Scenario: 默认 JSON 输出
- **WHEN** 用户执行 `edr file scan --mode=smart` 且未提供 `--excel`
- **THEN** 系统输出 JSON 数组到标准输出

#### Scenario: Excel 输出
- **WHEN** 用户执行 `edr file scan --mode=smart --excel=out.xlsx`
- **THEN** 系统生成 Excel 文件并在标准输出打印该路径

#### Scenario: Path 模式参数校验
- **WHEN** 用户执行 `edr file scan --mode=path` 但未提供 `--path`
- **THEN** 系统返回错误并以非 0 退出

### Requirement: 支持三种扫描模式
系统 SHALL 支持 `full`、`path`、`smart` 三种扫描模式。

#### Scenario: 全盘扫描
- **WHEN** `mode=full`
- **THEN** 系统扫描主机所有可用磁盘文件

#### Scenario: 指定路径扫描
- **WHEN** `mode=path` 且 `path=/tmp`
- **THEN** 系统仅扫描 `/tmp` 目录下的文件

#### Scenario: 智能扫描
- **WHEN** `mode=smart`
- **THEN** 系统按智能扫描管线处理目标列表

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
系统 SHALL 以 JSON/Excel 输出统一字段，包括 `path`, `size`, `modifiedTime`, `hashMd5`, `hashSha256`, `scanResult`, `scanMode`, `source`, `detectedBy`, `lastScanTime`, `trustedSignature`, `hostname`。

#### Scenario: 字段缺失处理
- **WHEN** 某字段不可获取
- **THEN** 对应字段输出为 `null`（JSON）或空单元格（Excel）
