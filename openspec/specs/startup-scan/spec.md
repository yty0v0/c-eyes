# Startup Scan

## Purpose

定义启动项扫描能力的命令接口、跨平台采集行为、过滤规则与输出契约，确保 `c-eyes startup-scan` 在 Windows 与 Linux 上以一致结构返回启动项资产数据，并明确该能力仅用于信息收集而不包含风险分析。

## Requirements

### Requirement: CLI 提供启动项扫描命令
系统 SHALL 提供 `c-eyes startup-scan` 命令用于执行本机启动项信息采集，并返回结构化结果。

#### Scenario: 默认执行扫描
- **WHEN** 用户执行 `c-eyes startup-scan` 且未提供过滤参数
- **THEN** 系统执行启动项采集并成功返回结果

### Requirement: 启动项采集不得依赖外部命令行
系统 MUST 仅通过进程内系统 API 或系统数据源完成启动项信息采集，不得调用外部命令行工具。

#### Scenario: 采集执行路径约束
- **WHEN** 系统执行启动项扫描
- **THEN** 采集流程不启动任何外部命令进程且可在 Windows/Linux 上完成采集

### Requirement: 支持定义的查询参数
系统 SHALL 支持以下查询参数用于过滤结果：`groups`、`hostname`、`ip`、`name`、`initLevel`、`defaultOpen`、`isXinetd`、`showName`、`user`、`enable`、`startType`、`publisher`。

#### Scenario: 模糊过滤生效
- **WHEN** 用户提供 `hostname`、`ip`、`name`、`showName`、`user` 或 `publisher` 参数
- **THEN** 系统按大小写不敏感的模糊匹配规则过滤结果

#### Scenario: 结构化过滤生效
- **WHEN** 用户提供 `groups`、`initLevel`、`defaultOpen`、`isXinetd`、`enable` 或 `startType` 参数
- **THEN** 系统仅返回满足对应过滤条件的启动项记录

### Requirement: Linux 平台启动项字段采集
系统 SHALL 在 Linux 平台采集启动项名称、默认启动模式、启动方式与运行级别状态信息，至少覆盖 `name`、`defaultOpen`、`initLevel`、`xinetd`、`rc0`、`rc1`、`rc2`、`rc3`、`rc4`、`rc5`、`rc6`、`rc7` 字段。

#### Scenario: Linux 字段填充
- **WHEN** 在 Linux 平台执行启动项扫描
- **THEN** 系统返回记录中包含并填充 Linux 相关字段，且字段键完整存在

### Requirement: Windows 平台启动项字段采集
系统 SHALL 在 Windows 平台采集并填充 `showName`、`user`、`enable`、`startType`、`publisher` 字段，并与通用主机元数据合并输出。

#### Scenario: Windows 字段填充
- **WHEN** 在 Windows 平台执行启动项扫描
- **THEN** 系统返回记录中包含并填充 Windows 相关字段，且字段键完整存在

### Requirement: 返回字段契约固定
系统 SHALL 以固定字段集合返回扫描记录，字段包含 `displayIp`、`externalIpList`、`internalIpList`、`bizGroupId`、`bizGroup`、`remark`、`hostTagList`、`hostname`、`name`、`defaultOpen`、`rc0`、`rc1`、`rc2`、`rc3`、`rc4`、`rc5`、`rc6`、`rc7`、`initLevel`、`xinetd`、`user`、`enable`、`startType`、`publisher`、`showName`。

#### Scenario: 字段完整输出
- **WHEN** 系统返回任意启动项记录
- **THEN** 记录中包含全部约定字段键，且字段名与契约保持一致

#### Scenario: 平台差异字段兜底
- **WHEN** 某字段因平台差异或权限限制无法获取
- **THEN** 系统返回该字段的 `null`（或空集合）值而非省略字段键

### Requirement: 启动项扫描支持 JSON 与 Excel 输出
系统 SHALL 支持将启动项扫描结果输出为 JSON 和 Excel 两种格式。

#### Scenario: JSON 输出
- **WHEN** 用户选择 JSON 输出或使用默认输出
- **THEN** 系统输出结构化 JSON，字段与契约一致

#### Scenario: Excel 输出
- **WHEN** 用户指定 Excel 输出
- **THEN** 系统生成包含契约字段列的 Excel 文件

### Requirement: 内外网 IP 采集语义与其他扫描能力一致
系统 SHALL 与其他扫描能力使用一致的主机 IP 采集与映射逻辑，确保 `displayIp`、`externalIpList`、`internalIpList` 语义一致。

#### Scenario: 主机 IP 字段对齐
- **WHEN** 启动项扫描返回结果
- **THEN** 主机 IP 相关字段命名与语义与既有扫描能力保持一致

### Requirement: 扫描范围仅限信息收集
系统 MUST 将启动项扫描限定为信息采集，不得在该能力内输出风险分析、风险等级或告警结论。

#### Scenario: 结果语义约束
- **WHEN** 启动项扫描完成
- **THEN** 输出仅包含启动项资产信息，不包含风险判定字段
