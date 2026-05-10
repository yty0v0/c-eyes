## Why

`benchmark` 模块虽然已经完成去脚本化，但最近一轮实测暴露出两个文档缺口：一是四套模板、四个基线级别中“不得再通过命令执行采集基线事实”的约束没有被明确记录；二是原生采集在权限或 API 选择不当时会把本应可判定的策略误报为 `unknown`。这些行为现在已经在实现中被修正，需要补入 OpenSpec，避免后续回退到命令采集或再次引入低可信结果。

## What Changes

- 明确 `benchmark` 在 `windows`、`linux`、`euleros`、`kylin` 四套模板下，所有基线级别都必须使用 Go 原生采集路径，不再依赖外部命令、脚本或 vendor 基线脚本回放来获取检查事实。
- 明确原生采集结果的可信性要求：当平台原生接口可以提供结论时，检查结果必须返回可判定值，而不是因为实现细节退化为 `unknown`。
- 明确 Windows 安全策略类检查必须通过本机原生安全接口采集，包括 SAM / LSA / Registry / NetAPI 等适用来源，并要求关键密码策略字段输出稳定结果。
- 明确当确实不存在足够可信的原生来源时，系统只能返回 `unknown`，不得静默回退到命令采集来“补值”。
- 记录维护侧验证要求：原生结果需要能够与平台命令行导出的真实策略进行对照校验，以证明语义一致。

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `benchmark-scan`: tighten native-only collection, result trustworthiness, and no-command fallback requirements across all templates and baseline levels.

## Impact

- Affected specs: `openspec/specs/benchmark-scan/spec.md`
- Affected code: `internal/benchmark/*`, especially Windows security policy collectors and Unix native benchmark collectors
- Affected validation: benchmark live tests, cross-template benchmark execution, and command-line parity verification for native policy fields
