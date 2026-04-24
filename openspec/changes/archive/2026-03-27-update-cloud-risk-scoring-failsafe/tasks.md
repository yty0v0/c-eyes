## 1. Cloud Scoring Model

- [x] 1.1 将多平台云聚合主分从平均型改为有效结果最高分（MAX）。
- [x] 1.2 定义“有效 provider”判定规则（成功且有有效结论），并剔除无效平台对主分的稀释影响。
- [x] 1.3 新增 `effective_average_score` 观测指标，仅使用有效 provider 作为分母。

## 2. Override And Fail-Safe

- [x] 2.1 增加恶意威胁标签一票否决标记与高危等级覆盖逻辑。
- [x] 2.2 增加检测阈值（`malicious>=3` 或检出率 `>5%`）风险兜底逻辑。
- [x] 2.3 增加 5 平台下 `pending/failed/timeout >= 3` 的故障安全判定（`分析中` / `可疑-需本地核实`）。

## 3. Output Contract

- [x] 3.1 扩展 `CloudAnalysis` 输出结构，增加 provider outcome/error 卡片与统计字段。
- [x] 3.2 在最终 `RiskAssessment` 阶段统一应用 cloud override/fail-safe 覆盖规则。
- [x] 3.3 增加新的风险等级常量（`高危`、`分析中`、`可疑-需本地核实`）。

## 4. Tests And Validation

- [x] 4.1 更新 `cloud_weight_profile_test.go`，覆盖 MAX 聚合、有效分母、一票否决、检测阈值、故障安全场景。
- [x] 4.2 更新 `analyzer_test.go`，覆盖最终风险级别覆盖与 fail-safe 结果输出。
- [x] 4.3 执行 `go test ./internal/riskanalysis -count=1` 与 `go test ./... -count=1` 验证回归。

## 5. Docs And Packaging

- [x] 5.1 更新 `docs/usage.md`，补充新评分与故障安全规则说明。
- [x] 5.2 重建 `dist-windows-amd64/edr.exe` 与 `dist-linux-amd64/edr` 以包含本次改动。
