# System Account Scan

## Purpose

定义系统账号信息采集能力的行为边界、输入过滤规则与跨平台输出契约，确保 `c-eyes account scan` 在 Linux 与 Windows 上以一致结构返回账号资产与配置数据，并明确该能力仅用于信息收集而不包含风险分析。

## Requirements

### Requirement: CLI 提供系统账号扫描命令
系统 SHALL 提供 `c-eyes account scan` 命令用于执行本机系统账号信息采集，并以结构化 JSON 输出结果。

#### Scenario: 默认执行扫描
- **WHEN** 用户执行 `c-eyes account scan` 且未提供过滤参数
- **THEN** 系统返回一个 JSON 对象，包含 `total` 与 `rows` 字段，并以成功状态退出

### Requirement: 账号信息采集不得依赖外部命令
系统 MUST 仅使用操作系统原生接口或系统文件解析方式获取账号信息，不得通过命令行调用外部工具进行采集。

#### Scenario: 扫描执行路径
- **WHEN** 系统执行账号扫描
- **THEN** 采集流程仅使用系统 API、系统文件读取与进程内解析逻辑，不启动外部命令进程

### Requirement: 支持定义的查询参数
系统 SHALL 支持以下查询参数：`groups`、`hostname`、`ip`、`status`、`name`、`home`、`lastLoginTime`、`gid`、`uid`，并按约定规则执行过滤。

#### Scenario: 模糊查询参数匹配
- **WHEN** 用户提供 `hostname`、`ip` 或 `home` 参数
- **THEN** 系统按大小写不敏感的子串匹配规则过滤结果

#### Scenario: 枚举与数值参数匹配
- **WHEN** 用户提供 `groups` 或 `status` 数组参数
- **THEN** 系统仅返回命中任一数组元素的账号记录

#### Scenario: 时间范围参数匹配
- **WHEN** 用户提供 `lastLoginTime` 时间范围
- **THEN** 系统仅返回最后登录时间位于该范围内的账号记录

### Requirement: 输出结构与字段完整性
系统 SHALL 按固定结构输出：顶层包含 `total` 与 `rows`；`rows` 中每条记录包含需求文档定义的账号字段集合，其中主机 IP 字段使用 `externalIpList` 与 `internalIpList` 表示。

#### Scenario: 字段完整输出
- **WHEN** 系统返回任意账号记录
- **THEN** 结果中包含定义的字段键，不因字段不可用而省略字段

#### Scenario: 不可用字段处理
- **WHEN** 字段因平台差异或权限限制无法采集
- **THEN** 该字段输出为 `null` 或空集合，且不影响该账号记录返回；`externalIpList/internalIpList` 在无数据时输出空数组

### Requirement: 账号扫描输出主机内外网 IP 列表
系统 SHALL 在账号扫描 `rows` 记录中输出 `internalIpList` 与 `externalIpList`，用于表达主机全量内外网 IPv4 地址。

#### Scenario: 列表字段输出
- **WHEN** 账号扫描输出任意记录
- **THEN** 结果包含 `internalIpList/externalIpList` 字段用于表达主机 IP 列表

#### Scenario: 仅内网地址主机
- **WHEN** 主机仅存在内网 IPv4 地址
- **THEN** `internalIpList` 包含全部内网地址，`externalIpList` 为空数组

### Requirement: Linux 平台账号数据采集
系统 SHALL 在 Linux 平台从系统账号相关数据源采集信息，包括账户基础信息、组信息、密码策略信息、SSH 公钥信息与 sudo 权限信息。

#### Scenario: Linux 账号基础信息
- **WHEN** 在 Linux 平台执行账号扫描
- **THEN** 系统从本机账号数据源填充 `name`、`uid`、`gid`、`home`、`shell`、`groups` 等字段

#### Scenario: Linux 扩展信息
- **WHEN** Linux 账号存在可访问的 `authorized_keys` 与 sudo 配置
- **THEN** 系统填充 `authorizedKeys`、`sudo` 与 `sudoAccesses` 字段

### Requirement: Windows 平台账号数据采集
系统 SHALL 在 Windows 平台使用系统账户 API 采集本地账号与组信息，并填充 Windows 专用字段。

#### Scenario: Windows 账号字段填充
- **WHEN** 在 Windows 平台执行账号扫描
- **THEN** 系统填充 `fullName`、`description`、`type`、`status` 等 Windows 相关字段

#### Scenario: Windows 组信息采集
- **WHEN** Windows 账号存在本地组或全局组归属
- **THEN** 系统将账号组信息写入 `groups` 字段

### Requirement: 扫描范围仅限信息收集
系统 MUST 将系统账号扫描限定为信息收集，不得在该能力中执行风险评估、风险分级或告警判定。

#### Scenario: 扫描结果语义
- **WHEN** 账号扫描执行完成
- **THEN** 输出仅包含账号资产与配置数据，不包含风险结论字段
