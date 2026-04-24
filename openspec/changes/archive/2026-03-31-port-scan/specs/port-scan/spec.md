## ADDED Requirements

### Requirement: CLI 提供端口扫描命令
系统 SHALL 提供 `edr port-scan` 命令用于执行本机端口信息采集，并返回结构化结果。

#### Scenario: 默认执行扫描
- **WHEN** 用户执行 `edr port-scan` 且未指定扫描模式
- **THEN** 系统使用 `tcp-connect` 模式执行扫描并成功返回结果

### Requirement: 端口采集不得依赖外部命令行
系统 MUST 仅通过进程内系统 API 或系统数据源完成端口信息采集，不得调用外部命令行工具。

#### Scenario: 采集执行路径约束
- **WHEN** 系统执行端口扫描
- **THEN** 采集流程不启动任何外部命令进程且可在 Windows/Linux 上完成采集

### Requirement: 支持两种扫描模式并定义默认值
系统 SHALL 支持 `tcp-connect` 和 `tcp-syn` 两种扫描模式，且默认模式 MUST 为 `tcp-connect`。

#### Scenario: 指定半开扫描
- **WHEN** 用户显式指定扫描模式为 `tcp-syn`
- **THEN** 系统按非全连接采集流程采集端口信息（不建立完整连接）并返回统一字段结果

### Requirement: 支持请求过滤参数
系统 SHALL 支持以下请求参数用于过滤结果：`groups`、`hostname`、`ip`、`proto`、`port`、`bindIp`、`processName`。

#### Scenario: 模糊过滤生效
- **WHEN** 用户提供 `hostname`、`ip` 或 `processName` 参数
- **THEN** 系统按大小写不敏感的模糊匹配规则过滤结果

#### Scenario: 结构化过滤生效
- **WHEN** 用户提供 `groups`、`proto`、`port` 或 `bindIp` 参数
- **THEN** 系统仅返回满足对应过滤条件的端口记录

### Requirement: 返回字段契约固定
系统 SHALL 以固定字段集合返回扫描结果，字段包含 `displayIp`、`externalIp`、`internalIp`、`bizGroupId`、`bizGroup`、`remark`、`hostTagList`、`proto`、`port`、`pid`、`processName`、`bindIp`、`status`。

#### Scenario: 字段完整输出
- **WHEN** 系统返回任意端口记录
- **THEN** 记录中包含全部约定字段键，且字段名与契约保持一致

#### Scenario: 不可用字段兜底
- **WHEN** 某字段因平台差异或权限限制无法获取
- **THEN** 系统返回该字段的 `null`（或空集合）值而非省略字段键

### Requirement: 支持 JSON 与 Excel 输出
系统 SHALL 支持将端口扫描结果输出为 JSON 和 Excel 两种格式。

#### Scenario: JSON 输出
- **WHEN** 用户选择 JSON 输出或使用默认输出
- **THEN** 系统输出结构化 JSON，字段与契约一致

#### Scenario: Excel 输出
- **WHEN** 用户指定 Excel 输出
- **THEN** 系统生成包含契约字段列的 Excel 文件

### Requirement: 扫描范围仅限信息收集
系统 MUST 将端口扫描限定为信息采集，不得在该能力内输出风险分析、风险等级或告警结论。

#### Scenario: 结果语义约束
- **WHEN** 端口扫描完成
- **THEN** 输出仅包含资产与连接相关信息，不包含风险判定字段
