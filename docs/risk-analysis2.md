1. 核心原则（V2）
-cloud-upload 默认关闭，显式开启才允许上传文件。
文件上传不是“hash miss 专属动作”，而是 最后一道防线：
前置阶段（白名单、YARA-X、本地/云哈希、模式内判定）都走完后，仍无法给出高置信结论，才上传。
不启用上传时，也要做“按分析量动态预算”，1条和100条不能同一最大时长。

2. 参数设计（最终）
-cloud-upload=false
-cloud-upload-concurrency=2
-cloud-upload-wait=0（0=按模式自动）
-cloud-upload-submit-timeout=20s
-cloud-upload-poll-interval=5s
-cloud-upload-max-size=20MB
-analysis-max-duration=0（0=智能计算）

3. 四种联网模式的统一流程
fast：白名单 -> 云哈希快查 -> 本地快速兜底 -> 评分
smart：白名单 -> 本地预扫 -> 云路由查询 -> 交叉校验评分
deep：先走smart -> 深度云动态查询 -> 交叉校验评分
cloud_only：白名单（可保留）-> 云哈希查询 -> 评分
然后统一进入“是否需要最终上传防线”判断。

4. 上传触发条件（最终防线）
满足全部条件才上传：
-cloud-upload=true
目标可上传（有文件路径、可读、非目录、大小<=max-size）
前置流程未得出“高置信结论”
高置信结论定义：
白名单 allow/deny 命中
本地高置信恶意命中（如本地分>=90）
云哈希高置信命中（如云分>=80）
或模式已有明确终判（极低风险或极高风险）
不满足高置信时才进入上传，作为最后防线补证据。

5. 智能时长计算（重点）
先定义：
N = 总记录数
U = 进入上传阶段的记录数
C = 上传并发（cloud-upload-concurrency）
5.1 不启用上传（cloud-upload=false）
自动总预算：
fast: T = clamp(15s + N*2s, 30s, 30m)
smart: T = clamp(40s + N*6s, 3m, 90m)
cloud_only: T = clamp(30s + N*4s, 2m, 60m)
deep: T = clamp(2m + N*20s, 20m, 240m)
5.2 启用上传（cloud-upload=true）
在对应“无上传预算”基础上增加：
T_upload = ceil(U/C) * (submit_timeout + wait_timeout + 2*poll_interval) * 1.2
最终总预算：
T_total = min(T_base + T_upload, mode_cap)
如果用户传了 -analysis-max-duration>0，优先用用户值做硬上限。

6. 模式默认等待（cloud-upload-wait=0 时）
fast = 10s
smart = 3m
cloud_only = 4m
deep = 6m

7. 五平台上传策略（含频率）
virustotal：启用上传，频率约4次/分钟，并发1，优先级高
triage：启用上传，频率约1次/3秒，并发2
hybrid_analysis：启用上传，频率约1次/5秒，并发2
malwarebazaar：默认不上传（隐私/公开样本风险），保留哈希查询
otx：当前不做文件上传，仅哈希情报查询

8. 结果输出新增字段
cloud_upload_enabled
cloud_upload_attempted
cloud_upload_status（completed|pending|skipped|failed）
cloud_upload_reason
cloud_upload_providers
cloud_upload_tasks（provider/task_id/status/score/link/error）
cloud_upload_duration_ms

9. 代码改造点
cmd/edr/main.go：新参数、自动预算注入
internal/riskanalysis/analyzer.go：最终防线上传判定、动态总时长控制
internal/riskanalysis/cloud.go：新增可选上传接口（不破坏现有Query）
internal/riskanalysis/cloud_multi.go：上传并发调度与平台限频
internal/riskanalysis/cloud_vt.go、cloud_triage.go、cloud_hybrid_analysis.go：上传与轮询实现
internal/riskanalysis/cloud_config.go + c-eyes-cloud.json：上传相关配置
internal/riskanalysis/types.go：输出字段扩展

10. 验收标准
不开 -cloud-upload 时，行为与当前版本兼容。
开启后，上传仅在“前置流程无法高置信判定”时触发。
批量样本下总时长随 N/U 自动增长，不再固定死值。
输出可清晰看到上传是否执行、是否完成、为何超时/跳过。

11.新增“高危短路判定”阶段（在白名单之后、最终评分之前）。
若满足任一条件，则不再执行加权/交叉校验，直接输出高危结果：
- 本地 YARA-X 出现高危命中（建议限定 severity >= 90 或 high_confidence 标签）。
- 任一云平台返回高危分（建议 provider_score >= 80）。
短路时最终分：final = max(local_high_score, cloud_max_high_score)，风险等级强制为“高风险”。
未触发短路时，继续走原有评分流程。
