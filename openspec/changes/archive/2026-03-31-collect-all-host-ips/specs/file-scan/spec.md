## ADDED Requirements

### Requirement: 文件扫描输出补齐主机 IP 字段
系统 SHALL 在文件扫描结果中输出主机维度字段 `displayIp`、`internalIp`、`externalIp` 及 `internalIpList`、`externalIpList`。

#### Scenario: 文件扫描主机字段
- **WHEN** 用户执行任意文件扫描模式
- **THEN** 每条结果记录包含主机 IP 单值字段与列表字段

#### Scenario: Excel 导出包含列表列
- **WHEN** 用户使用文件扫描 Excel 导出
- **THEN** 导出列中包含 `internalIpList` 与 `externalIpList`
