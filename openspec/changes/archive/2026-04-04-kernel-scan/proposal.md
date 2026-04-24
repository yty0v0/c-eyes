## Why

当前 EDR 扫描能力已覆盖端口、环境变量、计划任务等信息，但缺少统一的内核模块信息采集能力，导致主机内核态组件可见性不足。新增跨 Windows/Linux 的内核模块信息采集能力，可以补齐资产基线数据并支持后续检索与联动分析。

## What Changes

- 新增内核模块信息采集能力，覆盖 Windows 与 Linux 平台。
- 新增查询过滤参数：`groups`、`hostname`、`ip`、`moduleName`、`path`、`version`。
- 新增标准化返回字段，包含主机信息、模块基本属性、依赖关系与被依赖关系。
- 内外网 IP 改为数组化采集，返回全部可见地址，不再限定单值存储。
- 提供 JSON 与 Excel 两种导出格式，并通过命令行统一触发执行。
- 本次仅定义信息收集与导出能力，不包含风险分析、告警与处置逻辑。

## Capabilities

### New Capabilities
- `kernel-scan`: 跨平台采集主机内核模块信息，支持条件过滤与 JSON/Excel 导出。

### Modified Capabilities
- (none)

## Impact

- 受影响规范：新增 `kernel-scan` capability spec。
- 受影响代码：采集器模块、跨平台适配层、数据模型定义、CLI 参数与导出实现。
- 受影响数据：主机 IP 字段由单值转为多值表示（内外网地址集合）。
- 依赖与系统：复用现有扫描任务调度与导出链路，不引入外部服务依赖。
