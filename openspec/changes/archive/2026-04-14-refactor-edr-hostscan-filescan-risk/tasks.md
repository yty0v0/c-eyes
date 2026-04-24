## 1. CLI 入口与全局参数骨架

- [x] 1.1 重构 `cmd/edr` 根命令路由，仅暴露 `hostscan`、`filescan` 与全局 `-r/-o/-h`
- [x] 1.2 实现全局参数预解析（`-r/--riskanalyze`、`-o`、`--risk-mode`）并保留中文错误输出
- [x] 1.3 实现 `-o` 路径后缀格式识别（json/csv/xlsx）与非法后缀校验

## 2. hostscan 聚合执行器

- [x] 2.1 新增 hostscan 模块注册表，映射 `account,usergroup,process,port,startup,scheduledtask,environment,kernel,database,application`
- [x] 2.2 实现 `--custom`/`--all` 互斥校验与默认 all 选择逻辑
- [x] 2.3 实现 hostscan 单模块参数全集与多模块/all 参数交集校验
- [x] 2.4 实现 hostscan 多模块聚合输出与“完全一致记录”去重

## 3. filescan 双模式执行器

- [x] 3.1 新增 filescan Web 子模块注册表（`site/framework/jarpackage`）及默认 all 逻辑
- [x] 3.2 实现 filescan 本地文件扫描模式参数（`--scan-mode full|path|smart`，且 path 模式使用 `--scan-mode path <path>`）
- [x] 3.3 实现 filescan Web 子模块模式与本地文件模式互斥校验
- [x] 3.4 实现 filescan Web 聚合参数交集校验与“完全一致记录”去重

## 4. 风险分析全局化与串联流程

- [x] 4.1 将 `riskanalyze` 能力改为全局 `-r/--riskanalyze` 调度，支持独立输入源分析路径
- [x] 4.2 实现 `hostscan/filescan + -r` 串联执行，并确保仅输出风险分析结果
- [x] 4.3 实现 `--risk-mode` 默认 `smart`，并在 hostscan 串联场景限制为 `local_only`
- [x] 4.4 保留并迁移原风险分析参数到全局流程，补齐冲突与缺失参数中文报错

## 5. 统一输出与序列化适配

- [x] 5.1 抽象统一输出器，覆盖扫描结果与风险分析结果
- [x] 5.2 实现未传 `-o` 默认自动导出 `result*.xlsx` 与 JSON 文件输出路径
- [x] 5.3 实现 CSV 导出（字段展开策略与 UTF-8 编码）
- [x] 5.4 复用/扩展现有 Excel 导出能力以支持全局 `-o *.xlsx`

## 6. 帮助信息与兼容性收敛

- [x] 6.1 更新 `-h` 帮助文案，明确 hostscan/filescan 调用示例、参数互斥规则与模式说明
- [x] 6.2 在帮助中补充文件扫描三种模式与风险分析五种模式说明
- [x] 6.3 收敛旧命令入口，验证外部主流程仅剩 hostscan/filescan 两个扫描模块

## 7. 测试与回归验证

- [x] 7.1 新增/更新参数解析测试：互斥校验、默认值、交集参数、中文错误提示
- [x] 7.2 新增/更新执行流测试：`hostscan/filescan` 聚合、去重、`-r` 串联仅输出分析结果
- [x] 7.3 新增/更新输出测试：`-o` 后缀识别、json/csv/xlsx 导出与默认 stdout JSON
- [x] 7.4 运行核心测试并修复回归，确保改造后命令行为与规格一致

## 8. 稳定性与适度性能优化（真实数据反馈）

- [x] 8.1 修复 `filescan --scan-mode smart -r` 在异常 PE 导入表解析上的 panic，确保单样本异常不导致整批失败
- [x] 8.2 调整串联风险分析零记录行为：返回空数组 `[]` 且退出码为 0
- [x] 8.3 完成 `hostscan -r` 本地 YARA 路径候选映射扩展（`process/startup/scheduledtask/kernel/database/application`）并补齐 startup `execPath`
- [x] 8.4 增加云 provider 无效调用抑制：无 API key 跳过初始化、鉴权错误会话内熔断
- [x] 8.5 基于本地真实数据完成深测与 dist 验证，确认功能可用且无回归崩溃
