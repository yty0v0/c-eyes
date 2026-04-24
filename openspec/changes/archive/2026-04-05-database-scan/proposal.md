## Why

当前 EDR 缺少统一的数据库信息采集能力，无法在 Windows 和 Linux 上稳定输出可检索、可导出的数据库资产信息。需要补齐该能力，以支持后续资产盘点与运营分析场景。

## What Changes

- 新增跨平台数据库信息采集能力，覆盖 Windows 与 Linux。
- 定义数据库扫描请求过滤参数（业务组、主机名/IP、数据库类型/版本、端口、路径类条件）。
- 定义标准化返回字段，包含通用字段与平台/数据库特有字段。
- 明确仅进行信息收集，不包含风险分析结论或处置逻辑。
- 提供命令行入口，支持 JSON 与 Excel 两种结果输出格式。

## Capabilities

### New Capabilities
- `database-scan`: 提供跨平台数据库信息采集、过滤查询与标准化导出能力。

### Modified Capabilities
- 无。

## Impact

- Affected specs: 新增 `database-scan` capability spec。
- Affected code: 数据采集模块、跨平台适配层、CLI 参数解析、结果序列化与导出模块。
- Affected dependencies: 新增 Excel 导出依赖（Go 生态 xlsx 库）。
- Affected systems: Windows/Linux 终端环境下的本地数据库信息发现与汇总流程。
