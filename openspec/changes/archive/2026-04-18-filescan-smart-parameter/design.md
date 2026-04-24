## Context

`filescan` 当前把 `smart` 作为独立扫描模式，导致语义与执行边界不清晰：它既像“扫描范围”，又像“策略开关”。本次变更需要把“范围”（`full/path`）和“策略”（`--smart`）拆开，并且满足两个约束：  
1) `--smart` 只能在 `--scan-mode full|path` 下使用；  
2) `path + --smart` 只能在传入路径内选择高危/敏感子集。

同时，固定上限不适配不同体量主机，智能子集预算需要根据候选总量动态计算，并保持 `--max-targets` 的显式控制优先级。

## Goals / Non-Goals

**Goals:**
- 统一本地 filescan 参数语义：`--scan-mode` 仅定义扫描范围，`--smart` 仅定义是否启用智能子集策略。
- 在 `full/path + --smart` 下，仅扫描高危/敏感子集，并基于候选总量动态预算。
- 为结果输出增加 `smart_enabled`，使下游能够识别本次是否启用智能子集。
- 明确参数错误路径并提供稳定报错（尤其是 `--smart` 误用场景）。

**Non-Goals:**
- 不调整 Web 模块（`--custom/--all`）的业务逻辑与过滤模型。
- 不改动风险分析 `--risk-mode smart` 的语义（仅限 risk analysis 领域）。
- 不引入新的外部依赖或数据库结构迁移。

## Decisions

- **决策 1：移除 `--scan-mode smart`，新增 `--smart` 开关。**  
  - 方案 A（采纳）：`--scan-mode` 只允许 `full/path`；`--smart` 作为独立布尔参数。  
  - 方案 B（不采纳）：保留 `--scan-mode smart` 并同时支持 `--smart`。  
  - 选择原因：避免双入口语义冲突；满足用户要求“直接不兼容旧参数”。

- **决策 2：`--smart` 的合法组合严格校验。**  
  - `--smart` 仅允许与 `--scan-mode full` 或 `--scan-mode path <path>` 同时出现。  
  - 任何 `--smart` + (`--custom`/`--all`/缺失 `--scan-mode`) 均返回参数错误。  
  - 方案备选：弱校验并静默忽略非法组合（不采纳）。  
  - 选择原因：显式失败比隐式降级更安全，便于自动化脚本发现错误。

- **决策 3：智能子集采用“两阶段：候选枚举 -> 规则打分选取”。**  
  - 第一阶段按 `full/path` 枚举候选并计算候选总量 `N`。  
  - 第二阶段基于高危目录、敏感扩展名、近期变更等规则打分排序，选择前 `budget` 个目标。  
  - 方案备选：继续沿用当前独立 smart collector 流程（不采纳）。  
  - 选择原因：当前需求是“full/path 范围内的子集”，需要可解释的范围内筛选而非独立采样入口。

- **决策 4：预算采用动态分段 + 显式上限兜底。**  
  - 建议公式：  
    - `N <= 5,000`: `budget = ceil(N * 0.35)`  
    - `5,000 < N <= 50,000`: `budget = ceil(N * 0.15)`  
    - `N > 50,000`: `budget = ceil(N * 0.08)`  
    - 再执行 `budget = clamp(300, budget, 30000)`  
  - 若用户提供 `--max-targets > 0`，最终预算为 `min(budget, --max-targets)`。  
  - 方案备选：固定常量上限（不采纳）。  
  - 选择原因：在小盘/大盘设备上都能获得相对稳定的扫描成本。

- **决策 5：`path + --smart` 强制路径边界。**  
  - 高危/敏感目录规则只在传入路径子树内匹配，不允许回退到全局目录集合。  
  - 方案备选：path 下仍补充系统全局高危目录（不采纳）。  
  - 选择原因：严格符合用户定义的执行范围与预期。

- **决策 6：结果契约新增 `smart_enabled`。**  
  - 在本地 filescan 输出记录中新增 `smart_enabled: true|false`。  
  - `scan_mode` 维持 `full/path`，不再出现 `smart`。  
  - 方案备选：仅在顶层元信息或日志体现 smart 状态（不采纳）。  
  - 选择原因：逐条记录可被下游直接消费，不依赖额外上下文。

## Risks / Trade-offs

- **[候选枚举成本上升]** 先枚举后筛选会增加前置开销 -> 通过早停和轻量元数据读取控制遍历成本，并允许 `--max-targets` 进一步收敛。
- **[行为不兼容]** 旧脚本使用 `--scan-mode smart` 会直接失败 -> 在错误信息中给出替代用法 `--scan-mode full|path --smart`。
- **[子集漏检争议]** 子集策略可能遗漏低优先级样本 -> 通过清晰文档说明 `--smart` 是加速策略，默认 `full/path` 仍可做全量。
- **[规则可解释性]** 不同平台目录结构差异可能影响“高危目录”识别 -> 统一规则清单并在测试中覆盖 Windows/Linux 典型路径。

## Migration Plan

1. 更新参数解析与 help：移除 `--scan-mode smart`，增加 `--smart` 与组合校验。
2. 调整本地扫描参数结构与执行链路：`full/path` + `smart_enabled` 控制子集筛选。
3. 实现动态预算与 path 边界约束，并补充单元/集成测试。
4. 扩展输出结构增加 `smart_enabled`，更新 JSON/Excel 映射与文档示例。
5. 执行回归：参数冲突、path 边界、预算计算、风险串联流程。

## Open Questions

- 高危/敏感规则是否需要后续配置化（例如通过配置文件覆盖扩展名和目录权重）？本次先按内置规则实现。

## Post-implementation Notes (2026-04-18)

- Scope matching for `path + --smart` now normalizes trailing separators for drive-root paths. This prevents false out-of-scope filtering for descendants like `D:\folder\a.exe` when scope is `D:\`.
- Added explicit regression coverage for drive-root semantics to avoid future regressions in `isPathWithinScope` logic.
- Deep-test hardening included race detection pass and a test-stub concurrency fix (atomic call counters) in pipeline tests.
