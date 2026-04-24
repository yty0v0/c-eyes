## Why

当前 EDR 能力缺少统一的启动项信息采集模块，无法在 Windows 和 Linux 上以一致契约输出启动项资产信息。需要新增该能力以支撑资产盘点与基线核对，并明确本次范围仅做信息收集，不做风险分析。

## What Changes

- 新增 `edr startup-scan` 能力，支持 Windows/Linux 跨平台启动项信息采集。
- 支持请求过滤参数：`groups`、`hostname`、`ip`、`name`、`initLevel`、`defaultOpen`、`isXinetd`、`showName`、`user`、`enable`、`startType`、`publisher`。
- 固定返回字段契约：`displayIp`、`externalIpList`、`internalIpList`、`bizGroupId`、`bizGroup`、`remark`、`hostTagList`、`hostname`、`name`、`defaultOpen`、`rc0`、`rc1`、`rc2`、`rc3`、`rc4`、`rc5`、`rc6`、`rc7`、`initLevel`、`xinetd`、`user`、`enable`、`startType`、`publisher`、`showName`。
- 约束启动项采集必须使用进程内系统 API 或系统数据源，不得调用外部命令行工具。
- 输出支持 `json` 与 `excel` 两种格式，并通过命令行触发扫描与导出。
- 对齐内外网 IP 字段采集策略，保持与其他扫描能力的一致语义。

## Capabilities

### New Capabilities
- `startup-scan`: 定义跨平台启动项信息采集、过滤参数、字段契约与 JSON/Excel 输出行为。

### Modified Capabilities
- （无）

## Impact

- CLI：新增 `startup-scan` 子命令及查询参数解析。
- 采集层：新增 Windows/Linux 启动项采集实现与统一字段映射、空值兜底。
- 输出层：新增启动项扫描结果 JSON/Excel 序列化和 Excel 列映射。
- 测试与文档：补充跨平台采集、过滤、字段完整性与输出一致性验证。
