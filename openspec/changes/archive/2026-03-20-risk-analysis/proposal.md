## Why

当前扫描仅有原始结果，缺少统一、可量化的风险结论。引入本地 YARA-X 与云端威胁情报的双模式分析与加权评分，可让 EDR 在实时处置与溯源上更可用、可解释。

## What Changes

- 新增“风险分析”能力：读取指定扫描结果文件并生成结构化风险结论。
- 输入源扩展：支持 `-input`（JSON/NDJSON/Excel）、`-file`、`-dir -r`、`-pid`、`-pname`，并强制互斥校验。
- 支持本地匹配模式：集成 `yara-x` 引擎作为本地规则匹配。
- 本地安全回退：为避免跨主机同路径误扫，增加 `hostname/hash` 身份校验与 `local_fallback` 原因输出。
- 本地模式策略：`local_only` 下 YARA 不可用即报错退出；`hybrid` 下自动回退到 `cloud_only` 并告警。
- 支持高级进程内存分析：新增 `process_memory` 目标类型与 `-process-memory`/`-memory-max-bytes` 参数。
- 本地文件扫描改为分块读取：新增 `-yara-read-chunk`，降低大文件读取风险并可配置。
- 支持联网查询模式：对扫描结果进行云端威胁情报查询并评估风险。
- 联网模式固定多平台聚合：`virustotal`、`hybrid_analysis`、`malwarebazaar`、`otx`、`triage` 并行查询。
- 云端配置集中化：`api_key/base_url/proxy_url/rate_limit/timeout/cache_ttl` 统一从配置文件读取，支持全局代理与平台级覆盖。
- 云端权重与高置信规则补强：对各平台采用差异化权重，并对 MalwareBazaar/Triage 应用高危分值下限策略。
- 增加加权评分与风险等级划分（无/低/中/高）并输出 `risk_score` 与 `risk_level`。
- 输出支持 JSON 与 Excel 两种格式，参数可分别控制本地/云端/混合模式。
- 云端输出补充聚合标识：`cloud_analysis.cloud_provider=multi`，并新增 `cloud_analysis.cloud_providers` 记录实际参与聚合的平台列表。
- 云端配置文件路径策略明确：支持从 `EDR_CLOUD_CONFIG`、可执行文件同目录、当前目录、用户目录自动发现 `edr-cloud.json`。
- 兼容参数策略更新：`-cloud-provider` / `EDR_CLOUD_PROVIDER` 标记为废弃，联网模式固定多平台并行。
- 本地规则路径策略明确：`-yara-rules` > `EDR_YARA_RULES` > 可执行文件同目录 `rules/yaraRules|rules`。
- 新增项目根目录 `edr-cloud.json` 模板（仅模板，不默认打包进 `dist`）。
- 交付脚本完善：Windows/Linux 构建脚本在 `dist` 打包可执行文件、YARA-X 动态库与规则目录，实现开箱即用分发。
- 修复命令帮助展示：`edr process scan -h` 恢复完整参数列表显示。
- 规则质量修复：修正已发现的“永远不匹配”规则表达式，避免无效规则污染本地匹配结果。

## Capabilities

### New Capabilities
- `risk-analysis`: 基于扫描结果的双模式风险分析、加权评分、以及 JSON/Excel 输出。

### Modified Capabilities
- 

## Impact

- 新增风险分析模块、配置与 CLI 参数。
- 新增 `yara-x` 依赖与本地规则加载、匹配流程。
- 新增云端威胁情报多平台聚合客户端（含 API key、限频、缓存、容错、代理）。
- 新增进程内存采集能力（Windows）与非 Windows stub 行为。
- 风险分析与 `filescan/processscan` 的内置联动增强（无需先手工导出 JSON）。
- 增加 JSON/Excel 输出序列化与测试用例。
- 增加发布目录约定：`dist` 目录包含运行所需二进制与本地依赖；云端 key 配置文件与程序解耦，可独立下发与更新。
