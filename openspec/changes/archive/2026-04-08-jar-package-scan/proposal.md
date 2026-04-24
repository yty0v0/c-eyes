## Why

当前资产侧缺少统一的 Jar 包信息采集能力，难以稳定获得包名、版本、类型、可执行属性与绝对路径，导致主机软件依赖台账不完整，影响后续资产治理与关联分析。现在需要补齐一个可在 Windows 和 Linux 运行的跨平台采集能力，并与现有 CLI 导出流程对齐。

## What Changes

- 新增 EDR 的 Jar 包信息采集能力，面向主机维度输出标准化记录。
- 定义统一查询参数：`groups`、`hostname`、`ip`、`name`、`version`、`type`、`executable`、`path`。
- 定义统一返回结构，覆盖主机信息与 Jar 包核心字段（包名、版本、类型、可执行、绝对路径）。
- 约束采集边界为“仅信息收集，不做风险分析”。
- 要求采集实现不依赖外部命令行命令执行。
- 支持通过命令行触发扫描，并导出 JSON 与 Excel 两种结果格式（UTF-8）。
- 内外网 IP 调整为数组化采集，输出全量地址集合。
- 采集策略采用静态 + 动态结合方式，并与现有 Web 应用/站点扫描模块风格保持一致。

## Capabilities

### New Capabilities
- `jar-package-scan`: 跨平台 Jar 包信息采集与结构化导出能力，支持过滤查询、标准输出和 JSON/Excel 导出。

### Modified Capabilities
- 无

## Impact

- Affected specs: 新增 `openspec/changes/jar-package-scan/specs/jar-package-scan/spec.md`。
- Affected code: 预计涉及采集器模块、Jar 数据模型、CLI 参数绑定、过滤管线、JSON/Excel 导出与跨平台适配层。
- APIs/CLI: 新增或扩展 `edr jar-package-scan` 命令与参数。
- Dependencies: 可能复用现有导出组件，必要时复用/引入 Excel 导出能力（如 `excelize`）。
