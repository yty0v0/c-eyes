## MODIFIED Requirements

### Requirement: 输出结构与字段完整性
系统 SHALL 按固定结构输出：顶层包含 `total` 与 `rows`；`rows` 中每条记录包含需求文档定义的账号字段集合，其中主机 IP 字段使用 `externalIpList` 与 `internalIpList` 表示。

#### Scenario: 字段完整输出
- **WHEN** 系统返回任意账号记录
- **THEN** 结果中包含定义的字段键，不因字段不可用而省略字段

#### Scenario: 不可用字段处理
- **WHEN** 字段因平台差异或权限限制无法采集
- **THEN** 该字段输出为 `null` 或空集合，且不影响该账号记录返回；`externalIpList/internalIpList` 在无数据时输出空数组
