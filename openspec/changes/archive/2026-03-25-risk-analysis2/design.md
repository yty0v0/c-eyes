## Context

当前 `risk-analysis` 已具备本地 YARA-X、云哈希查询、多平台聚合和多模式分析能力，但“文件上传到云端沙箱”仍缺少统一边界：
- 上传触发与前置判定耦合不清，容易出现“过早上传”或“该上传未上传”。
- `analysis-max-duration` 在批量场景下缺少随样本规模变化的预算模型，导致 1 条与 100 条记录可能共享同一超时上限。
- 各模式（`fast`/`smart`/`deep`/`cloud_only`）在默认等待和执行阶段上存在行为差异，不利于可预测运维。

本次设计需要在保持现有兼容性的前提下，引入“默认关闭、按条件触发”的上传最终防线，并将时长预算改为可解释、可观测、可扩展的动态计算模型。

## Goals / Non-Goals

**Goals:**
- 建立统一上传触发契约：仅在前置流程无法形成高置信结论时才上传。
- 为四种联网模式提供一致的阶段化流程与默认等待策略。
- 提供基于 `N`（总记录）、`U`（进入上传阶段记录）、`C`（上传并发）的动态总时长预算。
- 扩展输出字段，明确上传是否启用、是否尝试、执行结果和失败原因。
- 增加高危短路判定，减少高危样本的延迟判定。

**Non-Goals:**
- 不新增新的云情报提供商。
- 不重写现有评分模型，只在高危短路命中时增加快速终判路径。
- 不改变 `-cloud-upload=false` 时的既有行为语义（兼容优先）。

## Decisions

### Decision 1: 上传能力采用“显式开启 + 最终防线”模型
- 选择：新增 `-cloud-upload`（默认 `false`），上传仅在满足全部条件时触发：
  - 上传开关开启；
  - 目标可上传（路径存在、可读、非目录、大小不超过 `-cloud-upload-max-size`）；
  - 前置流程未给出高置信终判。
- 原因：将上传从“常规流程”收敛为“补证据动作”，控制隐私与成本，同时降低误上传概率。
- 备选方案：
  - “hash miss 即上传”：实现简单，但噪声高且缺乏风控边界，放弃。
  - “按模式固定上传”：可控性一般，无法表达前置高置信短路，放弃。

### Decision 2: 统一四种联网模式的阶段模型
- 选择：
  - `fast`: 白名单 -> 云哈希快查 -> 本地快速兜底 -> 评分
  - `smart`: 白名单 -> 本地预扫 -> 云路由查询 -> 交叉校验评分
  - `deep`: 先走 `smart` -> 深度云动态查询 -> 交叉校验评分
  - `cloud_only`: 白名单（可保留）-> 云哈希查询 -> 评分
  - 四种模式在完成前置阶段后，统一进入“是否触发最终上传防线”判定。
- 原因：保证模式差异只体现在前置深度，而不体现在上传判定逻辑，降低维护复杂度。
- 备选方案：
  - 各模式独立上传判定分支：灵活但重复实现多，长期演进风险高，放弃。

### Decision 3: 定义“高置信结论”作为上传阻断条件
- 选择：以下任一成立即禁止上传：
  - 白名单 `allow`/`deny` 命中；
  - 本地高置信恶意命中（如 `local_score >= 90`）；
  - 云哈希高置信命中（如 `cloud_score >= 80`）；
  - 模式已得出明确终判（极低风险或极高风险）。
- 原因：优先使用低成本证据完成判定，上传只为补全证据链。
- 备选方案：
  - 仅依赖最终分数阈值判断：会忽略来源可信度差异，解释性不足，放弃。

### Decision 4: 引入动态总时长预算并保留用户硬上限
- 选择：
  - 当 `-analysis-max-duration=0` 时按模式自动计算基础预算 `T_base`；
  - 若启用上传，则增加上传预算 `T_upload`：
    - `T_upload = ceil(U/C) * (submit_timeout + wait_timeout + 2*poll_interval) * 1.2`
    - `T_total = min(T_base + T_upload, mode_cap)`
  - 当用户设置 `-analysis-max-duration>0` 时，作为全流程硬上限。
- 原因：让预算随样本规模和上传压力增长，减少批量任务误超时。
- 备选方案：
  - 固定超时：简单但不适配规模变化，放弃。
  - 仅按 `N` 线性增长：忽略上传轮询开销，精度不足，放弃。

### Decision 5: `-cloud-upload-wait=0` 采用模式化默认值
- 选择：`fast=10s`、`smart=3m`、`cloud_only=4m`、`deep=6m`。
- 原因：不同模式目标不同，默认等待应与分析深度匹配。
- 备选方案：
  - 全模式统一等待值：配置简单，但要么拖慢 fast，要么压缩 deep，放弃。

### Decision 6: 多平台上传策略采用“能力分层 + 限频调度”
- 选择：
  - 支持上传：`virustotal`、`triage`、`hybrid_analysis`；
  - 默认不上传：`malwarebazaar`（保留哈希查询）；
  - 仅哈希情报：`otx`；
  - 在 `cloud_multi` 统一执行并发调度与限频（provider 级预算）。
- 原因：在风险、隐私、稳定性之间平衡；避免每个 provider 自行实现调度逻辑。
- 备选方案：
  - 全 provider 统一上传：不符合平台能力与合规差异，放弃。
  - 完全串行上传：实现简单但吞吐低，放弃。

### Decision 7: 新增“高危短路判定”阶段
- 选择：在白名单后、最终评分前引入短路：
  - 本地 YARA-X 高危命中（如 `severity >= 90` 或 `high_confidence` 标签）；
  - 任一云平台高危分（如 `provider_score >= 80`）。
  - 命中后直接输出高风险，`final = max(local_high_score, cloud_max_high_score)`。
- 原因：降低高危样本响应时延，避免不必要的后续加权和交叉校验。
- 备选方案：
  - 保持仅最终加权后判定：一致性好但高危响应慢，放弃。

### Decision 8: 扩展输出契约以支持运维观测
- 选择：新增字段：
  - `cloud_upload_enabled`
  - `cloud_upload_attempted`
  - `cloud_upload_status`（`completed|pending|skipped|failed`）
  - `cloud_upload_reason`
  - `cloud_upload_providers`
  - `cloud_upload_tasks`（`provider/task_id/status/score/link/error`）
  - `cloud_upload_duration_ms`
- 原因：提升排障与审计能力，让“未上传/上传失败/上传超时”可区分。
- 备选方案：
  - 仅日志输出，不扩展结构化结果：对自动化消费不友好，放弃。

### Decision 9: 代码落点按职责拆分，避免横向污染
- 选择：
  - `cmd/edr/main.go`：新参数与自动预算注入；
  - `internal/riskanalysis/analyzer.go`：阶段编排、最终防线判定、总时长控制、短路判定；
  - `internal/riskanalysis/cloud.go`：上传接口抽象（兼容已有 Query）；
  - `internal/riskanalysis/cloud_multi.go`：并发调度、限频与聚合；
  - `internal/riskanalysis/cloud_vt.go`、`cloud_triage.go`、`cloud_hybrid_analysis.go`：上传提交与轮询；
  - `internal/riskanalysis/cloud_config.go` + `edr-cloud.json`：上传相关配置；
  - `internal/riskanalysis/types.go`：输出字段扩展。
- 原因：降低耦合，便于后续单元测试与 provider 增量扩展。
- 备选方案：
  - 将所有逻辑集中在 `analyzer.go`：短期快，长期维护成本高，放弃。

## Risks / Trade-offs

- [上传触发门槛过高导致漏补证据] -> 通过可配置阈值与灰度观察（统计 `attempted=false but unresolved=true`）校准。
- [上传触发门槛过低导致成本上升] -> 以高置信阻断规则为第一层阀门，并增加 provider 限频与并发上限。
- [动态预算过长影响交互体验] -> 允许用户显式设置 `-analysis-max-duration` 作为硬上限。
- [多平台调度导致部分 provider 饥饿] -> 在 `cloud_multi` 内实现公平轮转或配额保底策略。
- [高危短路误判放大] -> 将短路条件限定为高阈值与高置信标签，并保留证据字段供审计复核。
- [新增字段破坏下游解析] -> 保持向后兼容：新增可选字段，不移除既有字段。

## Migration Plan

1. 在 CLI 与配置层引入新参数，保持默认值与旧行为兼容（`-cloud-upload=false`）。
2. 实现上传接口与 `cloud_multi` 调度骨架，先接入 VT/Triage/Hybrid Analysis。
3. 在 `analyzer` 中接入统一阶段编排、最终防线判定与动态预算计算。
4. 扩展输出结构并补充序列化测试，确保 JSON/Excel 兼容。
5. 通过回归测试验证不开启上传时行为不变；再做开启上传的集成测试与限频压力测试。

回滚策略：
- 紧急情况下可通过配置将 `-cloud-upload=false` 全局关闭，退回无上传路径。
- 若调度逻辑引发问题，可临时将 `cloud-upload-concurrency` 降为 1 并提高轮询间隔，减轻外部依赖压力。

## Open Questions

- 各 provider 的上传失败重试策略是否统一（次数、退避、可中断条件）？
- `cloud_upload_tasks` 是否需要输出统一的 `provider_verdict` 字段，方便上层聚合展示？
- 对公开样本风险较高的平台（如 MalwareBazaar），是否需要增加组织级显式二次确认开关？
