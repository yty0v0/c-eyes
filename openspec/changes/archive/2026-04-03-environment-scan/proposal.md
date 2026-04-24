## Why

当前 EDR 资产采集能力缺少“环境变量信息”这一类基础数据，导致在跨平台主机排查与资产盘点时需要额外补充采集链路。现在补齐该能力，可以与现有扫描模块保持统一的数据契约与 CLI 使用方式，并满足 JSON/Excel 双格式导出需求。

## What Changes

- 新增环境变量采集能力，覆盖 Linux 与 Windows，支持按条件过滤并返回标准化结果。
- 明确采集路径约束：仅允许进程内 API/系统数据源采集，不允许通过外部命令行工具抓取环境变量。
- 定义输入参数与输出字段契约，重点将内外网 IP 统一为列表字段（`externalIpList`、`internalIpList`）。
- 增加输出格式要求：支持 JSON 与 Excel。
- 明确能力边界：只做信息收集与结构化输出，不包含风险分析和告警结论。

## Capabilities

### New Capabilities
- `environment-scan`: 定义环境变量信息采集的跨平台行为、过滤参数、输出契约与格式要求。

### Modified Capabilities
- 无。

## Impact

- 新增规范文件：`openspec/changes/environment-scan/specs/environment-scan/spec.md`。
- 后续实现可能涉及环境变量采集模块、跨平台采集适配层、CLI 参数解析与 JSON/Excel 输出层。
