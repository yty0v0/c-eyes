## Why

当前 `c-eyes filescan` 将 `smart` 作为独立 `--scan-mode`，无法表达“在 `full/path` 范围内做智能子集扫描”的需求，且用户侧难以理解执行边界。现在需要把智能能力改为显式参数并收敛行为，确保范围可控、输出可解释、参数错误可即时反馈。

## What Changes

- **BREAKING**: 移除 `--scan-mode smart`，`--scan-mode` 仅保留 `full` 与 `path`。
- 新增 `--smart` 布尔参数，仅允许与 `--scan-mode full` 或 `--scan-mode path <path>` 组合使用；否则返回参数错误。
- `--scan-mode path --smart` 仅在传入路径范围内选择高危/敏感目标子集，不允许越界扩展扫描范围。
- 智能子集不再使用固定上限，改为按候选总量动态计算预算；若显式提供 `--max-targets`，作为硬上限参与裁剪。
- 本地文件扫描输出新增 `smart_enabled` 字段，明确本次扫描是否启用智能子集策略。
- 更新 filescan 帮助文案、参数校验与对应测试，覆盖不兼容路径和错误提示。

## Capabilities

### New Capabilities
- (none)

### Modified Capabilities
- `filescan`: 调整统一入口参数契约，新增 `--smart` 组合约束并移除 `--scan-mode smart`。
- `file-scan`: 调整本地扫描模式与智能子集策略，新增 `smart_enabled` 输出字段与动态预算规则。

## Impact

- 影响 `cmd/edr/unified_cli.go` 中 filescan 参数解析、帮助输出、错误分支和回归测试。
- 影响 `internal/filescan` 本地目标收集与模式分发逻辑（`full/path + smart` 子集选择、动态预算、边界限制）。
- 影响 JSON/Excel 输出映射（新增 `smart_enabled`），以及相关文档和使用示例。

## Implementation Addendum (2026-04-18)

- Fixed a Windows scope edge case for `--scan-mode path <path> --smart`: when `<path>` is a drive root such as `D:\`, descendants on the same drive are now correctly treated as in-scope.
- Added a Windows drive-root regression scenario to the delta specs and a regression test in `internal/filescan/smart_subset_test.go`.
- During deep testing, fixed a test-only data race in `internal/filescan/pipeline_test.go` by using atomic counters so `go test -race` remains stable and actionable.
