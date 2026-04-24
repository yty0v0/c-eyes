## ADDED Requirements

### Requirement: 用户组扫描仅输出主机 IP 列表字段
系统 SHALL 在用户组扫描结果中仅使用 `externalIpList` 与 `internalIpList` 表达主机内外网 IP，且不再输出 `externalIp` 与 `internalIp` 单值字段。

#### Scenario: 多网卡主机输出
- **WHEN** 主机存在多个内网地址
- **THEN** `internalIpList` 返回全部内网地址

#### Scenario: 无外网地址输出
- **WHEN** 主机不存在外网地址
- **THEN** `externalIpList` 返回空数组
