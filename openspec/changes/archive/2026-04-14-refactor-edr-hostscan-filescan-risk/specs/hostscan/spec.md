## ADDED Requirements

### Requirement: hostscan 提供统一主机扫描入口
系统 SHALL 提供 `edr hostscan` 作为主机信息扫描唯一外部入口，支持 `--custom` 与 `--all` 模块选择。

#### Scenario: 默认执行 all 扫描
- **WHEN** 用户执行 `edr hostscan` 且未提供 `--custom/--all`
- **THEN** 系统按 `all` 选择执行全部 host 模块并返回聚合结果

#### Scenario: custom 与 all 互斥
- **WHEN** 用户同时提供 `--custom` 与 `--all`
- **THEN** 系统返回中文参数冲突错误并以非 0 退出

### Requirement: hostscan 模块标识与参数约束
系统 SHALL 支持模块标识 `account,usergroup,process,port,startup,scheduledtask,environment,kernel,database,application`。单模块请求使用该模块完整参数集，多模块或 all 请求仅允许参数交集。

#### Scenario: 单模块使用模块专属参数
- **WHEN** 用户执行 `edr hostscan --custom account` 并提供 account 专属参数
- **THEN** 系统接受请求并按 account 模块参数规则执行

#### Scenario: 多模块使用非交集参数
- **WHEN** 用户执行 `edr hostscan --custom account,process` 并提供仅 account 支持的参数
- **THEN** 系统返回中文参数错误并提示该参数不在聚合交集内

### Requirement: hostscan 聚合输出按完全一致记录去重
系统 MUST 在多模块或 all 场景下对结果执行“完全一致记录去重”，并输出单份汇总结果。

#### Scenario: 两条记录完全一致
- **WHEN** 不同模块返回两条字段和值完全一致的记录
- **THEN** 输出中仅保留一条记录

### Requirement: hostscan 与全局风险分析串联
当用户在 `hostscan` 命令上启用 `-r/--riskanalyze` 时，系统 SHALL 先完成 hostscan，再将扫描结果送入风险分析，并且仅输出风险分析结果。

#### Scenario: hostscan 串联风险分析
- **WHEN** 用户执行 `edr hostscan --custom process -r`
- **THEN** 系统输出风险分析结果，不输出原始扫描结果

#### Scenario: hostscan 风险模式限制
- **WHEN** 用户在 `hostscan -r` 场景设置非 `local_only` 风险模式
- **THEN** 系统返回中文错误，提示 hostscan 仅支持本地风险分析模式

### Requirement: hostscan 风险串联需为可落地模块提供本地分析目标路径
系统 SHALL 在 `hostscan -r` 场景下，为可落地到文件路径的模块输出本地分析所需的 `target_path` 候选映射，至少覆盖 `process,startup,scheduledtask,kernel,database,application`。

#### Scenario: startup 模块补充 execPath 用于风险串联
- **WHEN** 用户执行 `edr hostscan --custom startup -r`
- **THEN** 风险链路可使用 `execPath` 作为 `target_path` 候选进入本地 YARA 分析

#### Scenario: application 模块无扫描记录
- **WHEN** 用户执行 `edr hostscan --custom application -r` 且扫描结果为 0 条
- **THEN** 系统返回空分析数组 `[]`，并以退出码 0 结束
