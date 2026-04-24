## Context

此前为兼容历史消费者，我们在输出中同时保留了单值与列表两种内外网 IP 字段。随着跨模式统一工作完成，单值字段已成为重复来源，且在多网卡场景中容易让人误解为“唯一地址”。本次改造目标是简化契约：只输出列表字段。

## Goals / Non-Goals

**Goals:**
- 在四类扫描输出中删除 `externalIp/internalIp`，仅保留 `externalIpList/internalIpList`。
- 保持 `displayIp` 作为展示字段继续可用。
- 过滤逻辑仍支持 `ip` 模糊匹配，并基于 `displayIp + 列表 + 全部 IP` 工作。
- 更新导出和文档，避免新旧字段并存。

**Non-Goals:**
- 不修改 `displayIp` 的选主策略。
- 不变更 `ip` 查询参数语义。
- 不引入外部公网探测服务。

## Decisions

1. 数据模型统一  
   所有结果模型移除单值字段，仅保留列表字段；主机内部结构也不再保留单值内外网字段。

2. 配置结构统一  
   `edr-config` 使用 `externalIpList/internalIpList`，不再接收单值 `externalIp/internalIp`。

3. 兼容策略  
   本次为明确的非兼容变更，不保留旧字段回写，避免长期双轨维护。

4. 过滤策略  
   `hostIPMatch` 统一遍历 `displayIp`、`InternalIPs`、`ExternalIPs` 与 `IPs`，覆盖所有可见地址。

## Risks / Trade-offs

- [消费者兼容风险] -> 通过 OpenSpec、文档和示例明确迁移到列表字段。
- [旧配置失效风险] -> 文档更新配置示例并强调字段变更。
- [展示地址误解] -> 保留 `displayIp` 仅作为展示值，检索依赖列表字段。

## Migration Plan

- 第一步：移除类型中的单值字段并更新注入逻辑。
- 第二步：更新过滤、导出与文档。
- 第三步：执行全量测试与两平台 dist 重建。
- 第四步：在 OpenSpec 记录变更并归档。

## Open Questions

- 后续是否需要为列表字段增加稳定排序策略（例如按接口优先级）。
