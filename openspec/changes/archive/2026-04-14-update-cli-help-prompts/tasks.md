## 1. Root Help Rewrite

- [x] 1.1 重写 `cmd/edr/unified_cli.go` 的 `usage()` 输出，严格按 `change2.md` 的 `./edr -h` 示例结构与文案顺序展示
- [x] 1.2 在 `usage()` 中补全“指定分析源”五选一参数说明与“输出设置”说明

## 2. Subcommand Help Restructure

- [x] 2.1 重写 `hostscan -h` 帮助文案为参数导向分类，移除“规则”措辞
- [x] 2.2 重写 `filescan -h` 帮助文案为 Web 模块/本地扫描模式分类说明，移除“规则”措辞
- [x] 2.3 调整 `hostscan -r -h` 帮助展示，使其仅显示风险可用模块与可用参数

## 3. Standalone Risk Help & Validation

- [x] 3.1 重写 `cmd/edr/main.go` 中 `parseRiskFlags` 的 `Usage`，按分类展示 `edr -r -h` 帮助信息
- [x] 3.2 运行并验证关键帮助命令输出：`edr -h`、`edr hostscan -h`、`edr hostscan -r -h`、`edr filescan -h`、`edr -r -h`
- [x] 3.3 更新/新增受影响测试断言，确保帮助文案变更可回归验证
