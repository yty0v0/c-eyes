## Why

当前扫描输出同时保留 `externalIp/internalIp` 单值字段与 `externalIpList/internalIpList` 列表字段，接口语义重复，增加了消费端理解和处理成本。需要统一为“仅列表字段”，减少冗余并明确输出契约。

## What Changes

- 删除所有扫描输出中的 `externalIp` 与 `internalIp` 单值字段。
- 保留并统一使用 `externalIpList` 与 `internalIpList` 作为唯一内外网 IP 存储形式。
- 同步更新主机信息采集结构、过滤逻辑、Excel 导出列与文档示例。
- 配置字段从单值 `externalIp/internalIp` 迁移为 `externalIpList/internalIpList`。

## Capabilities

### New Capabilities
- （无）

### Modified Capabilities
- `process-info-scan`: 主机 IP 输出从单值迁移为仅列表字段。
- `system-account-scan`: 主机 IP 输出从单值迁移为仅列表字段。
- `file-scan`: 主机 IP 输出从单值迁移为仅列表字段。
- `user-group-scan`: 主机 IP 输出从单值迁移为仅列表字段。

## Impact

- 这是接口字段层面的非兼容变更，依赖 `externalIp/internalIp` 的消费者需改读列表字段。
- 影响模块：`internal/processscan`、`internal/accountscan`、`internal/filescan`、`internal/usergroupscan`、`cmd/edr` 导出层与文档。
- 测试与构建流程需要覆盖四类扫描输出与两平台打包产物。
