## Why

当前统一 CLI 的帮助文案仍然偏工程化，存在“规则化表述多、可用参数分类弱、示例不够聚焦”的问题。用户已经明确给出目标文案结构，需要将 `-h/--help` 输出统一调整为更直观的操作导向说明。

## What Changes

- 重写 `./edr -h` 的帮助输出，按指定示例展示常见命令场景、风险输入源和输出设置。
- 重写 `hostscan -h` 与 `filescan -h` 的帮助输出，去掉“规则”措辞，改为“可用参数/模块/模式”的简洁分类说明。
- 优化 `edr -r -h` 的帮助输出，按“分析源参数、分析模式参数、分析增强参数”分类展示。
- 在 `-r` 帮助场景下仅展示可用模块与可用参数，不展示不可用模块或无效参数组合。
- 保持现有参数解析和执行逻辑不变，本次仅调整 `-h/--help` 文案呈现。

## Capabilities

### New Capabilities
- `cli-help-prompts`: 统一定义 `edr`、`hostscan`、`filescan`、`-r` 四类入口在 `-h/--help` 下的文案结构、分类方式与示例输出约束。

### Modified Capabilities
- `hostscan`: 补充 `-r` 帮助场景下“仅展示可用模块与风险参数”的输出约束。
- `filescan`: 补充 Web 模式与本地扫描模式在帮助文案中的分类表达约束。
- `risk-analysis`: 补充 `edr -r -h` 帮助文案的参数分类展示约束。

## Impact

- 影响 `cmd/edr/unified_cli.go` 中 `usage/hostscanUsage/filescanUsage` 及风险帮助相关输出函数。
- 影响 `cmd/edr/main.go` 中 `parseRiskFlags` 的 `Usage` 文案输出。
- 影响 CLI 帮助相关测试断言（若存在基于旧文案的字符串匹配）。
