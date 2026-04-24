## Why

当前云端风险聚合会被“无效平台结果”稀释，导致单个平台高危命中可能被平均后落到低风险/无风险。  
在威胁情报场景下这会带来漏报风险，因此需要将聚合逻辑改为更保守的安全优先策略，并在多平台异常时启用故障安全结论。

## What Changes

- 将云平台基础分从简单平均/加权平均改为“有效结果最高分（MAX）”。
- 增加“有效平均分”观测字段，仅统计成功且有有效结论的平台，不再把失败/超时/无结果平台计入分母。
- 增加威胁标签一票否决：命中 `webshell`、`trojan` 等恶意标签时直接提升为高危告警。
- 增加检测阈值规则：当 `malicious>=3` 或检出率 `>5%` 时，强制进入风险态，避免误判“无风险”。
- 增加故障安全策略：5 个平台中 3 个及以上 `pending/failed/timeout` 时，不输出“无风险”，改为“分析中”或“可疑-需本地核实”。
- 扩展输出结构，增加 provider 级状态卡、错误卡与 fail-safe/override 标记，便于审计与排障。

## Capabilities

### New Capabilities
无

### Modified Capabilities
- `risk-analysis`: 调整云聚合评分规则、风险覆盖规则与异常故障安全结论输出。

## Impact

- 主要影响 `internal/riskanalysis`：`cloud_multi.go`、`analyzer.go`、`types.go`、`scoring.go`。
- 输出 JSON 增加多个 `cloud_analysis.*` 观测字段，影响 CLI/导出消费方。
- 需要补充/更新单元测试覆盖新规则与边界场景。
