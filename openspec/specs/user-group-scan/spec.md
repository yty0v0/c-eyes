# User Group Scan

## Purpose

定义用户组信息采集能力的行为边界、过滤规则与跨平台输出契约，确保 `c-eyes user-group scan` 在 Linux 与 Windows 上以一致结构返回用户组资产数据，并明确该能力仅用于信息收集而不包含风险分析。

## Requirements

### Requirement: CLI 提供用户组扫描命令
系统 SHALL 提供 `c-eyes user-group scan` 命令用于执行本机用户组信息采集，并输出结构化结果。

#### Scenario: 默认执行扫描
- **WHEN** 用户执行 `c-eyes user-group scan` 且未提供过滤参数
- **THEN** 系统返回包含 `total` 与 `rows` 的结果对象并成功退出

### Requirement: 用户组信息采集不得依赖外部命令
系统 MUST 仅使用操作系统原生 API 或系统文件解析方式采集用户组信息，不得通过命令行调用外部工具。

#### Scenario: 扫描执行路径
- **WHEN** 系统执行用户组扫描
- **THEN** 采集流程仅使用进程内解析逻辑与系统接口，不启动外部命令进程

### Requirement: 支持定义的查询参数
系统 SHALL 支持以下查询参数：`groups`、`hostname`、`ip`、`name`、`gid`，并按约定规则执行过滤。

#### Scenario: 模糊查询参数匹配
- **WHEN** 用户提供 `hostname`、`ip` 或 `name` 参数
- **THEN** 系统按大小写不敏感的子串匹配规则过滤结果

#### Scenario: 业务组参数匹配
- **WHEN** 用户提供 `groups` 数组参数
- **THEN** 系统仅返回业务组 ID 命中任一数组元素的记录

#### Scenario: Linux GID 参数匹配
- **WHEN** 用户在 Linux 环境提供 `gid` 参数
- **THEN** 系统仅返回 `gid` 精确匹配的用户组记录

### Requirement: 输出结构与字段完整性
系统 SHALL 按固定结构输出：顶层包含 `total` 与 `rows`；`rows` 中每条记录包含需求文档定义的字段集合。

#### Scenario: 字段完整输出
- **WHEN** 系统返回任意用户组记录
- **THEN** 结果中包含 `displayIp`、`externalIpList`、`internalIpList`、`bizGroupId`、`bizGroup`、`remark`、`hostTagList`、`hostname`、`name`、`gid`、`members`、`description` 字段键

#### Scenario: 平台差异字段处理
- **WHEN** 字段因平台差异不可用（如 Linux 无 `description` 或 Windows 无 `gid`）
- **THEN** 系统以 `null` 或空集合返回该字段且不省略字段键；`externalIpList/internalIpList` 在无数据时输出空数组

### Requirement: 用户组扫描仅输出主机 IP 列表字段
系统 SHALL 在用户组扫描结果中仅使用 `externalIpList` 与 `internalIpList` 表达主机内外网 IP，且不输出 `externalIp` 与 `internalIp` 单值字段。

#### Scenario: 多网卡主机输出
- **WHEN** 主机存在多个内网地址
- **THEN** `internalIpList` 返回全部内网地址

#### Scenario: 无外网地址输出
- **WHEN** 主机不存在外网地址
- **THEN** `externalIpList` 返回空数组

### Requirement: Linux 平台用户组数据采集
系统 SHALL 在 Linux 平台从系统组数据源采集用户组信息，至少覆盖组名、组 ID 与组成员信息。

#### Scenario: Linux 用户组字段填充
- **WHEN** 在 Linux 平台执行用户组扫描
- **THEN** 系统从本机组数据源填充 `name`、`gid`，并尽力填充组成员集合

### Requirement: Windows 平台用户组数据采集
系统 SHALL 在 Windows 平台使用系统账户/组 API 采集本地用户组信息，并填充 Windows 专用字段。

#### Scenario: Windows 用户组字段填充
- **WHEN** 在 Windows 平台执行用户组扫描
- **THEN** 系统填充 `name`、`description` 与 `members` 字段，其中 `members` 至少包含 `name` 与 `type`

### Requirement: 扫描结果支持 JSON 与 Excel 输出
系统 SHALL 支持用户组扫描结果以 JSON 与 Excel 两种格式输出。

#### Scenario: JSON 输出
- **WHEN** 用户选择 JSON 输出或使用默认输出
- **THEN** 系统输出结构化 JSON，字段名与规范保持一致

#### Scenario: Excel 输出
- **WHEN** 用户指定 Excel 输出参数
- **THEN** 系统生成包含规范字段列的 Excel 文件

### Requirement: 扫描范围仅限信息收集
系统 MUST 将用户组扫描限定为信息收集，不得在该能力中执行风险评估、风险分级或告警判定。

#### Scenario: 扫描结果语义
- **WHEN** 用户组扫描执行完成
- **THEN** 输出仅包含资产信息与元数据，不包含风险结论字段
