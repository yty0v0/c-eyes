## ADDED Requirements

### Requirement: 账号扫描输出主机内外网 IP 列表
系统 SHALL 在账号扫描 `rows` 记录中输出 `internalIpList` 与 `externalIpList`，用于表达主机全量内外网 IPv4 地址。

#### Scenario: 列表与单值兼容
- **WHEN** 账号扫描输出任意记录
- **THEN** 结果同时包含兼容单值字段 `internalIp/externalIp` 与新增列表字段 `internalIpList/externalIpList`

#### Scenario: 仅内网地址主机
- **WHEN** 主机仅存在内网 IPv4 地址
- **THEN** `internalIpList` 包含全部内网地址，`externalIpList` 为空数组
