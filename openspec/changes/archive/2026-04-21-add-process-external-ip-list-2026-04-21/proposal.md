## Why

当前 `c-eyes process scan` 仅输出主机级外网地址字段 `externalIpList`，无法表达“某个进程实际外联到了哪些公网 IP”。在溯源与横向分析场景中，这会导致进程维度证据不足。  
已实现的代码新增了进程维度外联字段，因此需要把输出契约同步到 OpenSpec，避免实现与规格偏离。

## What Changes

- 为进程扫描结果新增字段 `processExternalIpList`，用于表示该进程关联的外联公网 IPv4 地址列表。
- 明确 `processExternalIpList` 与 `externalIpList` 语义区别：
  - `processExternalIpList`：进程维度外联地址
  - `externalIpList`：主机维度外网地址
- 约束 `processExternalIpList` 在无数据时输出空数组 `[]`，不输出 `null`，并保持与现有输出字段风格一致。
- 保持现有 `externalIpList`/`internalIpList` 的行为不变，确保向后兼容。

## Capabilities

### New Capabilities

- 无

### Modified Capabilities

- `process-info-scan`: 扩展进程扫描输出字段契约，新增 `processExternalIpList` 并补充其语义与空值行为。

## Impact

- 受影响能力：`c-eyes process scan` 输出契约（JSON/导出结构中的进程记录字段）。
- 受影响代码：进程扫描输出模型、序列化与导出映射链路。
- 兼容性：新增字段为向后兼容扩展，旧消费者可忽略该字段；既有字段语义保持不变。
