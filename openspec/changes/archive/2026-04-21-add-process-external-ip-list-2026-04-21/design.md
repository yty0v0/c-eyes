## Context

`process-info-scan` 现有输出同时包含主机维度网络字段（`internalIpList`、`externalIpList`），但缺少进程维度外联地址。  
业务在排查可疑进程时，需要直接看到“该进程对应的外联公网 IP 列表”，而不是仅能看到主机公网地址集合。  
本次变更已在实现层新增 `processExternalIpList` 字段，设计文档用于明确契约边界、默认值行为与输出链路一致性。

## Goals / Non-Goals

**Goals:**
- 在不破坏现有输出契约的前提下，为每条进程记录补充 `processExternalIpList`。
- 明确字段语义：
  - `processExternalIpList` 表示进程维度外联公网 IPv4 列表。
  - `externalIpList` 继续表示主机维度外网 IPv4 列表。
- 统一空值行为：`processExternalIpList` 无数据时返回 `[]`。
- 保证 JSON 输出与导出链路（如 Excel）字段名与语义一致。

**Non-Goals:**
- 不新增 CLI 入参与过滤能力。
- 不改变 `externalIpList`、`internalIpList` 的已有定义与生成逻辑。
- 不引入新的风险评分、告警判定或连接行为分析逻辑。

## Decisions

1. **新增字段而非复用 `externalIpList`**
   - 决策：新增 `processExternalIpList`，保留 `externalIpList` 原语义。
   - 原因：复用/改写 `externalIpList` 会破坏既有消费方认知，并造成兼容性风险。
   - 备选方案：直接把 `externalIpList` 改为进程维度；已放弃，因属于潜在破坏性变更。

2. **字段默认值使用空数组**
   - 决策：`processExternalIpList` 无数据时返回 `[]`，不返回 `null`。
   - 原因：与现有 IP 列表字段风格一致，便于前端/脚本统一按数组处理。
   - 备选方案：返回 `null` 表示不可用；已放弃，因会增加消费端分支判断。

3. **仅在输出层扩展，不调整扫描入口协议**
   - 决策：保持 `c-eyes process scan` 调用方式不变，仅扩展结果字段。
   - 原因：用户体验稳定，升级成本低。
   - 备选方案：新增开关控制是否计算进程外联；当前不采用，避免参数复杂化。

4. **保持导出字段对齐**
   - 决策：JSON 与导出列（如 Excel）都包含 `processExternalIpList`。
   - 原因：避免不同输出通道字段不一致导致排障困难。

## Risks / Trade-offs

- [进程网络信息瞬时性导致结果不完整] → 通过文档明确“无观测数据返回空数组”，并避免将空数组解释为“绝对无外联”。
- [消费方误把 `processExternalIpList` 当作主机外网列表] → 在 spec 中显式区分两字段语义并补充场景示例。
- [新增字段后导出模板未同步] → 通过任务清单覆盖 JSON 与导出链路校验，确保输出一致。

## Migration Plan

1. 合并后按原命令 `c-eyes process scan` 发布，无需参数迁移。  
2. 消费方可按需读取 `processExternalIpList`；未升级消费方可忽略新增字段。  
3. 若发现兼容性问题，可临时在消费端忽略该字段，不影响既有字段解析。

## Open Questions

- 当前无阻塞发布的开放问题。
