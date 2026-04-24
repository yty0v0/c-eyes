## 1. CLI 参数契约调整

- [x] 1.1 在 `cmd/edr/unified_cli.go` 移除 `--scan-mode smart` 解析分支，仅保留 `full/path`
- [x] 1.2 新增 `--smart` 布尔参数解析，并实现校验：仅允许与 `--scan-mode full|path` 组合
- [x] 1.3 增加参数冲突错误分支（`--smart` 与 `--all/--custom` 或缺失 `--scan-mode` 时报错）
- [x] 1.4 更新 filescan help 文案，明确 `--scan-mode full/path` 与 `--smart` 的约束关系
- [x] 1.5 在 `c-eyes filescan -h` 的 `OPTIONS` 中新增并对齐 `--smart` 行，写清用途，并在同一行用括号标注使用条件（only valid with `--scan-mode full|path`）

## 2. 本地扫描执行与智能子集

- [x] 2.1 在 `internal/filescan` 参数结构中引入 `smart_enabled`（执行控制与输出字段所需）
- [x] 2.2 重构本地扫描入口：`full/path` 负责确定范围，`--smart` 决定是否进行高危/敏感子集筛选
- [x] 2.3 实现智能子集动态预算计算（基于候选总量），并将 `--max-targets` 作为硬上限裁剪
- [x] 2.4 实现 `path + --smart` 边界约束，确保所选目标严格位于传入路径子树内

## 3. 输出映射与文档同步

- [x] 3.1 在文件扫描结果结构中新增 `smart_enabled` 字段，并保持 `scan_mode` 仅为 `full/path`
- [x] 3.2 更新 JSON/Excel 映射逻辑，确保 `smart_enabled` 可稳定导出
- [x] 3.3 更新相关使用文档与示例命令，移除 `--scan-mode smart`，补充 `--smart` 用法

## 4. 测试与回归验证

- [x] 4.1 更新/新增 `cmd/edr/unified_cli_test.go`：覆盖 `--smart` 合法组合、非法组合、旧参数拒绝与 help 文案
- [x] 4.2 更新/新增 `internal/filescan` 测试：覆盖动态预算、path 边界、子集筛选与 `smart_enabled` 输出
- [x] 4.3 执行 `go test ./...`，确认 filescan 本地模式与风险串联流程无回归（`tmp/software-deeptest` 存在既有双 main 构建冲突；`cmd/edr` 与 `internal/*` 全部通过）

## 5. Post-implementation Addendum (2026-04-18)

- [x] 5.1 修复 `path + --smart` 在 Windows 盘符根路径（如 `D:\`）下的作用域匹配问题，确保同盘子路径不会被误判为越界
- [x] 5.2 新增 Windows 盘符根路径边界回归覆盖（`internal/filescan/smart_subset_test.go`）
- [x] 5.3 深度测试中修复 `internal/filescan/pipeline_test.go` 测试桩并发计数 race（改为 atomic），并补跑 `go test -race ./cmd/edr ./internal/filescan`
