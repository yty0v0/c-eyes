## Why

当前资产侧缺少统一的 Web 框架信息采集能力，无法稳定输出框架名称、版本、部署路径与关联组件信息，影响资产盘点与后续分析流程。现在需要补齐一个可在 Windows 和 Linux 运行的跨平台采集模块，并与现有命令行工具集成，支持标准化导出格式以便对接外部系统。

## What Changes

- 新增 EDR 的 Web 框架信息采集能力，面向主机维度收集框架与服务信息。
- 定义统一查询参数：业务组、主机名、IP、框架名、版本、语言类型、服务类型。
- 定义统一返回结构，覆盖主机信息、框架信息、站点信息、目录信息和关联 jar 列表。
- 约束采集边界为“仅信息收集，不做风险分析”。
- 要求采集实现不依赖通过命令行执行系统命令获取信息。
- 支持通过命令行触发工具执行，并导出 JSON 与 Excel 两种结果格式（UTF-8）。
- 内外网 IP 调整为数组化采集，支持完整地址集合输出。
- 采集策略采用静态 + 动态结合方式，并与现有 Web 应用扫描/站点扫描能力保持风格一致。

## Capabilities

### New Capabilities
- `web-framework-scan`: 跨平台 Web 框架信息采集与结果导出能力，提供过滤查询、结构化输出和 JSON/Excel 导出。

### Modified Capabilities
- 无

## Impact

- Affected specs: 新增 `openspec/changes/web-frame/specs/web-framework-scan/spec.md`。
- Affected code: 预计涉及采集器模块、数据模型定义、CLI 参数绑定、导出组件（JSON/Excel）以及跨平台适配层。
- APIs/CLI: 新增或扩展 Web 框架扫描命令与参数。
- Dependencies: 可能新增 Go Excel 导出库（如 `excelize`）或复用现有导出组件。
