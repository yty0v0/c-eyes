## Context

当前统一 CLI 帮助由两部分组成：
- `cmd/edr/unified_cli.go`：`edr -h`、`hostscan -h`、`filescan -h` 以及串联风险帮助补充输出。
- `cmd/edr/main.go`：`edr -r -h` 通过 `parseRiskFlags` 的 `FlagSet.Usage` 输出帮助。

问题在于帮助文案目前偏“规则描述”，且不同入口存在风格不一致。需求明确要求：
- `./edr -h` 按给定示例固定输出；
- 其他帮助文案改为参数导向分类；
- `-r` 场景只展示可用模块/参数，不展示不可用项。

## Goals / Non-Goals

**Goals:**
- 重写 `edr -h`，严格对齐给定示例结构。
- 将 `hostscan/filescan/-r` 帮助改为“可用参数分类”风格，移除“规则”措辞。
- 在 `hostscan -r -h` 下仅展示风险可用模块（6个）及风险可用参数。
- 保持既有参数解析、互斥校验、执行流程完全不变。

**Non-Goals:**
- 不修改扫描与风险分析逻辑。
- 不改动非帮助场景下的错误提示文本。
- 不调整输出文件格式与默认输出策略。

## Decisions

### Decision 1: 保持现有帮助路由逻辑，仅替换文案函数内容
- 方案：继续沿用 `runHostscanCLI/runFilescanCLI/runStandaloneRiskCLI` 的分支流程，不改变分支条件。
- 原因：当前逻辑已经正确区分全局帮助、聚合帮助、单模块帮助与风险帮助，改动最小风险最低。
- 备选：重构为统一帮助渲染器；放弃原因是本次仅文案重构，收益低于风险。

### Decision 2: 让 `hostscanUsage/filescanUsage` 接收风险上下文并输出可用集合
- 方案：把 `hostscanUsage` 改为接收 `riskEnabled + modules`，在 `-r` 场景只打印风险可用模块。
- 原因：可直接满足“不能使用的模块参数不要展示”。
- 备选：保留全模块列表并增加备注；放弃原因是与需求冲突（仍展示不可用项）。

### Decision 3: `edr -r -h` 改为定制分类输出
- 方案：修改 `parseRiskFlags` 中 `Usage` 文案，按“分析源 / 分析模式 / 分析增强 / 输出设置”组织。
- 原因：该入口由 `parseRiskFlags([]string{"-h"})` 触发，改这里可覆盖 `edr -r -h` 与 `edr -r --help`。
- 备选：在 `unified_cli.go` 增加单独 `riskUsage` 调用替代；放弃原因是重复逻辑、耦合更高。

### Decision 4: 单模块帮助继续复用模块解析器
- 方案：保留 `printHostscanModuleHelp/printFilescanWebModuleHelp` 现有行为，仅保留对旧输出参数的过滤与说明。
- 原因：符合“以最新代码逻辑为标准”，不引入额外行为变化。
- 备选：改成统一新入口命令形式；放弃原因是会偏离当前路由逻辑并扩大影响面。

## Risks / Trade-offs

- [风险] 帮助文案字符串变更可能导致现有测试断言失效  
  → Mitigation：同步更新/补充 `cmd/edr/unified_cli_test.go` 相关字符串断言。

- [风险] `hostscan -r -h` 文案与实际可用参数不一致  
  → Mitigation：文案由 `riskEnabled` 和模块集合驱动，且沿用现有参数可用性判断函数。

- [权衡] 为满足示例“完全替换”，`edr -h` 信息密度更偏示例而非技术总览  
  → Mitigation：将详细参数分类放在子帮助（`hostscan/filescan/-r`）中承接。

## Migration Plan

1. 修改 `unified_cli.go` 帮助输出函数及调用签名。
2. 修改 `main.go` 中 `parseRiskFlags` 的 `Usage` 文案分类。
3. 运行 `go test ./cmd/edr -run UnifiedCLI -v` 与相关测试验证。
4. 手工执行 `go run ./cmd/edr ... -h` 关键命令检查展示结果。
5. 在 `tasks.md` 勾选完成项。

## Open Questions

- 无。用户已明确确认文案范围与展示策略（只改帮助文案、`edr -h` 完全按示例、不可用项不展示）。
