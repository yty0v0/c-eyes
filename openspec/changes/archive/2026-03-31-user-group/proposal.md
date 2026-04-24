## Why

当前 EDR 已覆盖进程与账号等信息采集，但缺少统一的用户组信息采集能力，导致 Windows 与 Linux 上的用户组资产难以按同一契约检索与导出。需要补齐该能力以支持资产盘点与后续治理流程，并明确本次范围仅做信息收集，不包含风险分析。

## What Changes

- 新增用户组信息采集能力，支持 Windows 与 Linux 双平台。
- 新增 `edr user-group scan` 命令，支持按 `groups`、`hostname`、`ip`、`name`、`gid` 进行过滤查询。
- 约束采集实现不得通过外部命令行工具获取数据，必须使用系统原生 API 或系统文件解析。
- 统一输出结构，支持 JSON 与 Excel 两种结果格式。
- 明确输出语义仅为信息收集结果，不输出风险判定字段。

## Capabilities

### New Capabilities
- `user-group-scan`: 定义跨平台用户组信息采集的 CLI 行为、过滤参数、输出字段与导出格式契约。

### Modified Capabilities
- （无）

## Impact

- CLI 层新增 `edr user-group scan` 子命令与参数校验逻辑。
- 采集层新增 Windows/Linux 用户组枚举与字段映射模块。
- 输出层新增用户组结果的 JSON/Excel 序列化与表头定义。
- 测试与文档需覆盖跨平台字段差异、过滤行为与非命令行采集约束。
