## ADDED Requirements

### Requirement: filescan 提供统一文件扫描入口
系统 SHALL 提供 `edr filescan` 作为文件信息扫描统一入口，支持 `--custom` 与 `--all` 选择 `site/framework/jarpackage` 子模块；当未显式提供模块选择时默认执行 `all`。

#### Scenario: 默认执行 web 子模块 all 扫描
- **WHEN** 用户执行 `edr filescan` 且未提供 `--custom/--all`
- **THEN** 系统默认执行 `site/framework/jarpackage` 全部子模块并输出聚合结果

#### Scenario: 自定义多模块扫描
- **WHEN** 用户执行 `edr filescan --custom site,framework`
- **THEN** 系统仅执行 site 与 framework 两个子模块并输出合并结果

#### Scenario: custom 与 all 同时出现
- **WHEN** 用户执行 `edr filescan --custom site --all`
- **THEN** 系统返回中文参数冲突错误并以非 0 退出

### Requirement: filescan 支持本地文件扫描模式且与 web 子模块互斥
系统 SHALL 在 `filescan` 中支持本地文件扫描模式 `full/path/smart`（默认 `smart`），并且本地文件模式与 `site/framework/jarpackage` 选择 MUST 互斥。

#### Scenario: 本地 smart 扫描并串联风险分析
- **WHEN** 用户执行 `edr filescan --scan-mode smart -r`
- **THEN** 系统执行本地文件 smart 扫描并进入风险分析流程

#### Scenario: web 子模块与本地模式混用
- **WHEN** 用户执行 `edr filescan --custom site --scan-mode smart`
- **THEN** 系统返回中文错误，提示两类模式不能同时启用

### Requirement: filescan 聚合参数与去重规则
在 `site/framework/jarpackage` 多模块或 all 场景下，系统 SHALL 仅接受子模块参数交集，并对输出结果按“完全一致记录”去重。

#### Scenario: web 聚合使用非交集参数
- **WHEN** 用户在 `edr filescan --all` 请求中提供非交集参数
- **THEN** 系统返回中文参数错误并拒绝执行

#### Scenario: web 聚合去重
- **WHEN** 两个子模块产生字段和值完全一致的记录
- **THEN** 输出中仅保留一条记录

### Requirement: filescan 串联风险分析仅输出分析结果
当用户在 `filescan` 命令上启用 `-r/--riskanalyze` 时，系统 SHALL 在扫描完成后执行风险分析，并且仅输出分析结果。

#### Scenario: filescan 默认风险模式
- **WHEN** 用户执行 `edr filescan -r` 且未提供风险模式
- **THEN** 系统以 `smart` 作为默认风险分析模式

#### Scenario: filescan -r 输出行为
- **WHEN** 用户执行任意 `filescan` + `-r` 组合
- **THEN** 系统只输出风险分析结果，不输出扫描结果

### Requirement: filescan 本地扫描在异常二进制样本上保持稳定
系统 MUST 在本地文件扫描与串联风险分析中，对异常或损坏的 PE 导入表解析进行容错处理，避免进程级崩溃。

#### Scenario: 智能扫描遇到异常 PE 样本
- **WHEN** 用户执行 `edr filescan --scan-mode smart -r`，目标集中包含导入表损坏的 PE 文件
- **THEN** 系统跳过异常字段并继续处理其余记录，不发生 panic
