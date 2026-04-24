## Context

当前代码库已有 `environment-scan`、`port-scan`、`scheduled-task-scan` 等能力，但缺少统一的内核模块信息采集能力。新能力要求在 Windows 与 Linux 上一致输出结构化结果，且不通过命令行工具拼接调用系统命令，避免解析不稳定和权限差异导致的行为漂移。该能力主要服务资产可见性和后续联动分析，因此本次范围仅包含采集、过滤与导出。

## Goals / Non-Goals

**Goals:**
- 提供跨平台内核模块信息采集能力，统一字段与返回结构。
- 支持基于业务组、主机与模块属性的过滤查询。
- 支持 JSON 与 Excel 两种导出格式，并复用现有 CLI 使用方式。
- 将内外网 IP 字段升级为数组，返回全部可见 IP。

**Non-Goals:**
- 不实现风险打分、告警判定或自动处置。
- 不引入远程依赖服务或额外数据库迁移。
- 不改变其他既有扫描模块的业务语义。

## Decisions

1. 采集架构采用统一接口 + 平台实现分离。
- Decision: 定义 `KernelScanProvider` 抽象接口，按 `GOOS` 选择 Windows/Linux 实现。
- Rationale: 复用统一业务流程，同时隔离平台差异。
- Alternative: 在单实现中使用大量 `runtime.GOOS` 分支。
  - Rejected because: 可读性差且难以测试。

2. 禁止通过 shell 命令采集内核模块信息。
- Decision: 仅使用系统 API、procfs/sysfs、驱动信息接口或语言级系统调用读取数据。
- Rationale: 避免命令依赖、文本解析脆弱性与执行权限不一致。
- Alternative: 调用 `lsmod`/`modinfo`/`wmic` 等命令。
  - Rejected because: 不满足需求约束且跨平台一致性弱。

3. 统一数据模型并升级 IP 为数组。
- Decision: `externalIps[]`、`internalIps[]` 作为主机网络地址集合；模块记录包含 `moduleName`、`description`、`path`、`version`、`size`、`depends[]`、`holders[]`。
- Rationale: 与多网卡、多地址场景匹配，避免单值字段信息丢失。
- Alternative: 保持单值 `externalIp/internalIp`。
  - Rejected because: 无法表达完整网络视图。

4. 过滤语义与导出能力沿用现有扫描框架。
- Decision: `hostname/ip/moduleName/path` 使用模糊匹配；`groups/version` 使用集合过滤；导出层复用现有 JSON/Excel 写出器。
- Rationale: 降低实现成本并保持用户体验一致。
- Alternative: 新建独立导出链路。
  - Rejected because: 会造成重复实现与维护负担。

## Risks / Trade-offs

- [不同内核版本导致字段可见性差异] -> 统一字段做空值兜底并记录采集来源，保证结构稳定。
- [权限不足导致采集不完整] -> 返回部分结果并附带采集状态，不因单机失败中断整体任务。
- [IP 数组改动影响下游消费方] -> 在变更文档中明确字段升级，并在导出层保持列名可预期。
- [模糊匹配在大规模数据下性能波动] -> 优先在内存前置过滤可索引字段，必要时增加批量分页。

## Migration Plan

1. 新增 `kernel-scan` 能力实现与 CLI 子命令参数绑定。
2. 接入统一导出层，完成 JSON 与 Excel 输出映射。
3. 补充 Windows/Linux 双平台测试用例与样本数据校验。
4. 发布后观察导出兼容性；如出现解析问题，可临时降级为仅 JSON 输出。

## Open Questions

- Windows 平台内核模块描述字段在不同版本上的可用性是否需要分级回退策略。
- Excel 导出中 `depends/holders` 数组字段是以分隔字符串还是多列展开形式呈现（默认先按分隔字符串输出）。
