## ADDED Requirements

### Requirement: 用户组扫描输出主机内外网 IP 列表
系统 SHALL 在用户组扫描 `rows` 记录中输出 `internalIpList` 与 `externalIpList`，用于表达主机全量内外网 IPv4 地址集合。

#### Scenario: 多内网地址返回
- **WHEN** 主机存在多个内网 IPv4 地址
- **THEN** `internalIpList` 返回全部内网地址且不丢失原有 `internalIp` 兼容字段

#### Scenario: 无外网地址返回
- **WHEN** 主机不存在可识别的外网 IPv4 地址
- **THEN** `externalIpList` 返回空数组，`externalIp` 保持 `null` 或兼容值
