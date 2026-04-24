## Why

当前 EDR CLI 的扫描入口分散在多个子命令，参数命名和输出选项不统一，导致批量使用、自动化集成和风险分析联动成本高。需要将能力收敛为 `hostscan` 与 `filescan` 两个主模块，并统一 `-r` 与 `-o` 的全局行为，保证操作一致性与可维护性。

## What Changes

- 新增 `hostscan` 聚合入口，统一承载账户、用户组、进程、端口、启动项、计划任务、环境变量、内核、数据库、Web 应用等主机信息扫描能力。
- 新增 `filescan` 聚合入口，统一承载 `site/framework/jarpackage` 三类 Web/文件信息扫描能力，并保留本地文件扫描流程用于 `-r` 联动。
- `--custom` 与 `--all` 互斥；默认不传时 `hostscan/filescan` 均按 `all` 执行。
- 新增全局风险分析开关 `-r/--riskanalyze`，支持“直接分析输入文件”与“扫描后串联分析”两种方式；`-r` 默认模式为 `smart`。
- 新增全局输出参数 `-o`，直接接收输出文件路径并按后缀识别格式（`.json/.csv/.xlsx`）；使用 `-o` 时必须指定路径，不使用 `-o` 时默认在当前目录自动导出 `result*.xlsx`。
- 调整 filescan 本地 `path` 模式写法为 `--scan-mode path <path>`；不再支持 `--scan-path`。
- 扫描聚合结果在多模块/all 场景下仅按“记录完全一致”规则去重。
- CLI 帮助与参数错误提示统一中文；参数冲突、缺失与非法值返回非 0 退出码。
- 扩展 `hostscan -r` 的本地 YARA 目标映射能力，使 `process/startup/scheduledtask/kernel/database/application` 可通过路径候选进入本地分析链路；`startup` 输出补充 `execPath` 字段用于风险链路。
- 在串联风险分析场景中，若扫描结果为 0 条，返回空分析结果数组 `[]`（退出码 0），不再因“无记录”直接失败。
- 修复 `filescan --scan-mode smart -r` 在异常/损坏 PE 样本上的导入表解析崩溃，保证单样本异常不会中断整批分析。
- 对云分析 provider 增加无效调用抑制：未配置 API key 的 provider 启动时跳过；出现鉴权类错误时在当前执行会话内熔断该 provider，减少重复无效请求。
- **BREAKING**：CLI 主入口将由历史分散命令收敛到 `hostscan/filescan` 与全局 `-r/-o` 组合，部分旧命令路径将不再作为默认使用方式。

## Capabilities

### New Capabilities
- `hostscan`: 提供主机信息扫描的统一命令入口、模块选择、参数交集约束与聚合去重输出契约。
- `filescan`: 提供文件/站点信息扫描的统一命令入口、模块选择规则、默认 all 行为与风险联动入口。
- `global-output`: 定义全局 `-o` 的路径后缀识别与统一输出行为，覆盖扫描与风险分析结果。

### Modified Capabilities
- `risk-analysis`: 将风险分析能力升级为全局参数 `-r/--riskanalyze`，并定义与 `hostscan/filescan` 串联时仅输出分析结果。
- `file-scan`: 调整为 `filescan` 体系下的本地扫描子能力，保留 `smart` 默认语义并与新增全局参数协同。

## Impact

- 影响 `cmd/edr` 主入口命令路由、参数解析、帮助输出与错误处理。
- 影响主机与文件扫描聚合层的参数映射、结果合并与去重逻辑。
- 影响风险分析入口、模式参数命名冲突处理与输出链路。
- 影响本地文件元数据提取的稳定性与容错策略（异常 PE 样本不再导致进程崩溃）。
- 影响云分析 provider 的初始化与错误恢复策略（无 key 跳过、鉴权错误熔断）。
- 影响现有单模块命令测试、帮助文档和示例命令，需要同步更新。
