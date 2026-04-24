## Why

当前主机 IP 采集仅输出单个 `internalIp` / `externalIp`，在多网卡环境下会丢失可观测信息并导致不同扫描模式间 IP 表现不一致。需要统一升级为“收集全部内外网 IP”，同时保持已有单值字段兼容，避免影响现有调用方。

## What Changes

- 将主机 IP 采集升级为全量收集，新增 `internalIpList` 与 `externalIpList`。
- 保留原有 `internalIp` / `externalIp` 单值字段作为兼容字段。
- 将升级后的主机 IP 元数据统一应用到 `process scan`、`account scan`、`user-group scan`、`file scan`。
- 更新各模式 Excel 导出列，新增列表字段导出。
- 统一验证 Windows/Linux 构建与运行输出。

## Capabilities

### New Capabilities
- （无）

### Modified Capabilities
- `process-info-scan`: 增加进程扫描输出中的内外网 IP 列表字段。
- `system-account-scan`: 增加账号扫描输出中的内外网 IP 列表字段。
- `file-scan`: 增加文件扫描输出中的主机内外网 IP 字段与列表字段。
- `user-group-scan`: 增加用户组扫描输出中的内外网 IP 列表字段。

## Impact

- 影响模块：`internal/processscan`、`internal/accountscan`、`internal/usergroupscan`、`internal/filescan`、`cmd/edr` Excel 导出层。
- 影响输出契约：新增 `internalIpList` / `externalIpList`，并在文件扫描结果新增主机 IP 字段。
- 兼容性：保留原有单值字段，不破坏旧消费者。
