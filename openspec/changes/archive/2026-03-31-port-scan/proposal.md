## Why

当前 EDR 能力缺少统一的端口信息采集模块，无法在 Windows 和 Linux 上以一致契约输出端口、进程、绑定地址与内外网可达性信息。需要新增该能力以支撑资产盘点与排查效率，并明确本次范围仅做信息收集，不做风险分析。

## What Changes

- 新增 `edr port-scan` 能力，支持 Windows/Linux 跨平台采集端口信息。
- 提供两种扫描模式：`tcp-connect`（默认）和 `tcp-syn`（半开扫描）。
- 新增查询参数：`groups`、`hostname`、`ip`、`proto`、`port`、`bindIp`、`processName`。
- 固定返回字段契约，覆盖 `displayIp`、`externalIp`、`internalIp`、`bizGroupId`、`bizGroup`、`remark`、`hostTagList`、`proto`、`port`、`pid`、`processName`、`bindIp`、`status`。
- 输出支持 `json` 与 `excel` 两种格式，并通过命令行触发扫描与导出。
- 约束采集实现不得依赖外部命令行工具，必须使用进程内系统 API 或系统数据源。

## Capabilities

### New Capabilities
- `port-scan`: 定义跨平台端口信息采集、扫描模式、过滤参数、字段契约与 JSON/Excel 输出行为。

### Modified Capabilities
- （无）

## Impact

- CLI：新增 `port-scan` 子命令、扫描模式参数与过滤参数解析。
- 采集层：新增 Windows/Linux 端口与进程映射采集实现，统一字段补齐与状态映射。
- 输出层：新增端口扫描结果的 JSON/Excel 序列化和表头映射。
- 测试与文档：补充跨平台场景、参数过滤、扫描模式默认值与输出一致性验证。
