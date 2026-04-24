## ADDED Requirements

### Requirement: 进程扫描输出主机内外网 IP 列表
系统 SHALL 在每条进程扫描记录中输出 `internalIpList` 与 `externalIpList`，分别表示主机所有内网与外网 IPv4 地址集合。

#### Scenario: 多网卡主机输出
- **WHEN** 主机存在多个内网 IPv4 地址
- **THEN** `internalIpList` 返回全部内网地址，且保持 `internalIp` 兼容字段可用

#### Scenario: 无外网地址输出
- **WHEN** 主机未识别到外网 IPv4 地址
- **THEN** `externalIpList` 返回空数组，`externalIp` 为 `null` 或兼容值
