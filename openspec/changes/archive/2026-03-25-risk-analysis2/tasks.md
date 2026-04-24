## 1. CLI 参数与配置模型

- [x] 1.1 在 `cmd/edr/main.go` 增加上传相关参数：`-cloud-upload`、`-cloud-upload-concurrency`、`-cloud-upload-wait`、`-cloud-upload-submit-timeout`、`-cloud-upload-poll-interval`、`-cloud-upload-max-size`
- [x] 1.2 在 `cmd/edr/main.go` 增加 `-analysis-max-duration` 智能预算入口（`0` 代表自动计算）
- [x] 1.3 在 `internal/riskanalysis/cloud_config.go` 与 `edr-cloud.json` 增加上传策略配置项并补充默认值
- [x] 1.4 为新增参数与配置添加校验逻辑（并发、时长、大小上限必须为有效范围）

## 2. 分析流程编排与最终防线

- [x] 2.1 在 `internal/riskanalysis/analyzer.go` 抽象四种联网模式的“前置阶段 -> 最终上传判定”统一流程
- [x] 2.2 实现“高置信结论阻断上传”判定（白名单 allow/deny、本地高置信、云哈希高置信、模式终判）
- [x] 2.3 实现目标可上传性校验（路径存在、可读、非目录、大小不超限）
- [x] 2.4 确保 `-cloud-upload=false` 时完全不走上传路径并保持旧行为兼容

## 3. 高危短路判定与评分衔接

- [x] 3.1 在 `analyzer` 中新增白名单后、最终评分前的高危短路阶段
- [x] 3.2 接入本地高危命中条件（如 `severity >= 90` 或高置信标签）并短路到高风险
- [x] 3.3 接入云平台高危分条件（如 `provider_score >= 80`）并短路到高风险
- [x] 3.4 短路路径输出统一最终分计算规则：`final = max(local_high_score, cloud_max_high_score)`

## 4. 上传接口、多平台调度与限频

- [x] 4.1 在 `internal/riskanalysis/cloud.go` 增加可选上传接口，保持现有 `Query` 兼容
- [x] 4.2 在 `internal/riskanalysis/cloud_multi.go` 实现上传任务并发调度与 provider 级限频控制
- [x] 4.3 在 `internal/riskanalysis/cloud_vt.go` 实现 VirusTotal 上传提交与轮询查询
- [x] 4.4 在 `internal/riskanalysis/cloud_triage.go` 实现 Triage 上传提交与轮询查询
- [x] 4.5 在 `internal/riskanalysis/cloud_hybrid_analysis.go` 实现 Hybrid Analysis 上传提交与轮询查询
- [x] 4.6 明确 MalwareBazaar/OTX 默认仅做哈希情报查询，不进入文件上传执行队列

## 5. 动态总时长预算与模式默认等待

- [x] 5.1 在 `analyzer` 实现 `N/U/C` 驱动的动态预算计算（含 `T_base`、`T_upload`、`T_total`）
- [x] 5.2 实现 `-cloud-upload-wait=0` 的模式默认等待映射（`fast=10s`、`smart=3m`、`cloud_only=4m`、`deep=6m`）
- [x] 5.3 将用户 `-analysis-max-duration>0` 作为全流程硬上限覆盖自动预算
- [x] 5.4 增加预算计算日志与诊断信息，便于定位超时来源（基础预算或上传预算）

## 6. 输出字段扩展与序列化

- [x] 6.1 在 `internal/riskanalysis/types.go` 扩展上传可观测字段：`cloud_upload_enabled/attempted/status/reason/providers/tasks/duration_ms`
- [x] 6.2 更新 JSON 输出逻辑，确保上传未触发、触发中、完成、失败四类状态可区分
- [x] 6.3 更新 Excel 导出字段映射，补充上传状态及任务摘要列
- [x] 6.4 保持向后兼容：新增字段为可选，不破坏现有消费方

## 7. 测试与回归验证

- [x] 7.1 新增单元测试覆盖上传触发门槛与“高置信阻断上传”逻辑
- [x] 7.2 新增单元测试覆盖动态预算公式与 `-cloud-upload-wait=0` 默认值解析
- [x] 7.3 新增单元测试覆盖高危短路触发与未触发分支
- [x] 7.4 新增集成测试覆盖 `-cloud-upload=false` 与当前版本行为兼容
- [x] 7.5 新增集成测试覆盖批量样本下 `N/U` 增长导致总预算增长
- [x] 7.6 新增输出契约测试验证新增字段在 skipped/completed/failed 场景下正确填充

## 8. 文档与运维说明

- [x] 8.1 更新风险分析参数文档，说明上传默认关闭与最终防线触发条件
- [x] 8.2 补充多平台上传策略与限频说明（VT/Triage/Hybrid Analysis 上传，MalwareBazaar/OTX 哈希查询）
- [x] 8.3 补充动态预算说明文档，解释 `N/U/C` 与用户硬上限优先级
- [x] 8.4 增加排障指南：如何通过新增输出字段判断“未上传/超时/失败/已完成”
