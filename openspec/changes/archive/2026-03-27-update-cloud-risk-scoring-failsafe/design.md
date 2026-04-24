## Context

当前 `internal/riskanalysis/cloud_multi.go` 的聚合流程以平均型思路为主，存在以下问题：
- 高分被低质量/无结果平台稀释，导致高风险样本可能降级。
- 平台失败、超时、缺 key 等异常缺少统一 outcome 统计，难以观测与审计。
- 在多平台退化时存在 fail-open 风险，可能输出“无风险”。

本次改动涉及 `cloud_multi.go`、`analyzer.go`、`types.go`、`scoring.go` 及相关测试，属于跨模块行为变更。

## Goals / Non-Goals

**Goals:**
- 将云端基础风险改为有效结果最高分（MAX）聚合。
- 为云结果加入一票否决、检测阈值兜底和故障安全结论。
- 输出 provider 级别 outcome/error 观测信息，便于排障。
- 保持现有 CLI 参数兼容，不新增用户侧参数。

**Non-Goals:**
- 不改动各云平台底层 API 调用协议与鉴权流程。
- 不新增额外云厂商。
- 不调整已有本地 YARA 规则及本地打分公式。

## Decisions

### 1) 聚合主分改为 MAX（安全优先）
- 方案 A（采用）：对“有效 provider”取最高分作为云基础分。
- 方案 B（放弃）：继续加权平均并通过阈值补偿。
- 选择理由：方案 A 不会因无效低分稀释高危命中，更符合威胁检测场景。

### 2) 保留有效平均分仅用于观测
- 在 `CloudAnalysis` 新增 `effective_average_score`，仅用于调试和审计。
- 最终风险计算链路继续使用 MAX 基础分，避免语义冲突。

### 3) 增加 provider outcome/error 结构化输出
- 新增 `provider_outcome_card` 和 `provider_error_card`。
- 统一 outcome 分类：`success|no_result|failed|timeout|pending`。
- 选择理由：让“为什么没结论”可追踪，不再依赖日志猜测。

### 4) 将覆盖判定放在 analyzer 统一收口
- `cloud_multi` 负责产生 override/fail-safe 标记。
- `analyzer` 在最终 `RiskAssessment` 阶段应用覆盖逻辑（critical/pending/offline-suspicious）。
- 选择理由：保证最终等级判定路径单一，减少分支分散。

### 5) 故障安全采用 fail-closed
- 规则：总平台数 >= 5 且 unresolved >= 3 触发 fail-safe。
- 含 pending 时给 `分析中`，否则给 `可疑-需本地核实`。
- 选择理由：平台大面积不可用时避免误报“无风险”。

## Risks / Trade-offs

- [风险] 告警数量上升（更保守策略）  
  → Mitigation: 保留 `provider_outcome_card` 与覆盖标记便于 SOC 快速解释与分流。

- [风险] 新增风险等级（`高危`/`分析中`/`可疑-需本地核实`）可能影响下游展示  
  → Mitigation: 在 `docs/usage.md` 明确字段语义，并保持 `risk_score` 连续可读。

- [风险] 各平台返回结构差异导致“有效结论”判定边界复杂  
  → Mitigation: 用统一 helper（标签、检出率、verdict 判定）并以单测固化边界。

## Migration Plan

1. 更新云聚合与风险覆盖代码（`cloud_multi.go`, `analyzer.go`）。  
2. 扩展数据结构和风险等级常量（`types.go`, `scoring.go`）。  
3. 增加/更新单测覆盖核心场景。  
4. 运行 `go test ./...` 回归验证。  
5. 同步文档并重建发行包（Windows/Linux）。

回滚策略：
- 若出现兼容性问题，可回滚到本变更前提交，恢复平均聚合与旧风险等级映射。

## Open Questions

- 是否需要在 CLI 进度阶段对 fail-safe 增加显式提示（例如“云平台退化，采用离线可疑策略”）？
- 是否将恶意标签关键词表下放到配置文件，以便 SOC 团队自定义？
