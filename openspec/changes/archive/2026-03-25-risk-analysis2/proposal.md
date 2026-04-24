## Why

当前风险分析在“是否上传样本到云端”与“总分析时长预算”上缺少统一、可观测且可控的规则：上传触发边界不清晰，批量样本场景下时长策略不随分析规模变化。随着多云平台联动增强，需要将上传能力收敛为默认关闭、按条件触发的“最后防线”，并让时长预算按分析规模动态计算。

## What Changes

- 新增可显式开关的云端样本上传能力，默认关闭，仅在满足“最终防线”条件时触发上传。
- 新增并统一上传参数：`-cloud-upload`、`-cloud-upload-concurrency`、`-cloud-upload-wait`、`-cloud-upload-submit-timeout`、`-cloud-upload-poll-interval`、`-cloud-upload-max-size`。
- 在 `fast`、`smart`、`deep`、`cloud_only` 四种模式中统一“前置判定流程 + 最终上传防线判定”的执行结构。
- 明确“高置信结论不上传”规则：白名单 `allow/deny`、本地高置信命中、云哈希高置信命中、或模式已明确终判时，不进入上传阶段。
- 引入智能总时长预算模型：基于总记录数 `N`、进入上传阶段记录数 `U`、并发 `C` 动态计算分析时长；用户显式 `-analysis-max-duration` 仍为硬上限。
- 规定 `-cloud-upload-wait=0` 时按模式自动等待值，避免不同模式默认行为不一致。
- 定义多平台上传策略与限频：支持 VirusTotal/Triage/Hybrid Analysis 上传，MalwareBazaar 与 OTX 保持哈希情报查询策略。
- 扩展结果输出字段，新增上传开关、尝试状态、原因、任务明细和耗时等可观测信息。
- 新增“高危短路判定”阶段：在白名单之后、最终评分之前，命中高危条件时直接输出高风险结果。

## Capabilities

### New Capabilities

- 无

### Modified Capabilities

- `risk-analysis`: 调整风险分析流程与输出契约，新增最终防线上传触发规则、动态时长预算、模式默认等待、高危短路判定，以及上传执行可观测字段。

## Impact

- 受影响代码：
  - `cmd/edr/main.go`
  - `internal/riskanalysis/analyzer.go`
  - `internal/riskanalysis/cloud.go`
  - `internal/riskanalysis/cloud_multi.go`
  - `internal/riskanalysis/cloud_vt.go`
  - `internal/riskanalysis/cloud_triage.go`
  - `internal/riskanalysis/cloud_hybrid_analysis.go`
  - `internal/riskanalysis/cloud_config.go`
  - `internal/riskanalysis/types.go`
- 受影响配置：
  - `edr-cloud.json`
- 受影响接口/产物：
  - 风险分析 CLI 参数集合
  - 风险分析 JSON/Excel 输出字段（新增上传相关字段）
