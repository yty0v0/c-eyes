## Context

当前代码已具备风险分析主干能力：
- 模式与编排：`local_only` / `cloud_only` 与新引入的 `fast` / `smart` / `deep`。
- 本地匹配：`YaraXMatcher` 可对文件/内存执行本地规则匹配。
- 云端聚合：`MultiCloudClient` 支持多平台查询与阶段化路由（fast/smart/deep）。
- 现状短板：白名单判定过于单一（主要依赖 `signature_valid=true`），缺乏证书黑名单、BYOVD 过滤、哈希权威库与 LOLBin 命令行级例外，存在误放行空间。

约束：
- 不破坏现有 `risk analyze` CLI 与 JSON/Excel 输出兼容性。
- 保持“先低成本过滤，再高成本分析”的漏斗原则。
- 保持本地判定可解释、可审计（落地到输出字段）。

## Goals / Non-Goals

**Goals:**
- 建立多维白名单漏斗，并将其作为 `smart/deep` 的强前置。
- 以“拒绝优先于允许”为核心，补齐证书黑名单与 BYOVD 拦截。
- 引入权威哈希库（NSRL/企业基线）与本地安全信誉缓存（TTL）。
- 对 LOLBin 改为命令行级白名单，而非文件级免检。
- 输出白名单决策证据（来源、规则、原因）以支持审计与调优。

**Non-Goals:**
- 本变更不实现完整 SOC 编排、隔离动作执行器或沙箱平台管理控制台。
- 本变更不内置全量第三方情报数据，只定义加载与匹配框架。
- 不改变现有 YARA 规则语义，仅调整进入 YARA 的前置条件与优先级。

## Decisions

### 1) 新增 Whitelist Engine 作为统一判定入口

决策：在 `internal/riskanalysis` 增加 `WhitelistEngine`，接口形态建议：
- `Evaluate(ctx, meta, record) -> verdict`
- `verdict` 包含：`decision(allow|deny|continue)`、`reason`、`policy_id`、`evidence`、`confidence`。

理由：
- 当前逻辑分散在 `Analyzer` 中，难以扩展多维白名单。
- 统一引擎便于测试、热更新和审计输出。

备选：在 `Analyzer` 里硬编码 if-else。
- 放弃原因：策略会快速膨胀，维护成本与误判风险高。

### 2) 漏斗优先级采用“拒绝 > 允许 > 继续分析”

决策：判定顺序固定为：
1. 本地缓存（malicious/safe）
2. 权威哈希库（NSRL、企业基线）
3. 签名与发布者（Trusted Publishers）
4. 证书黑名单（revoked/stolen）与 BYOVD 驱动库（任何阶段命中都可直接 deny）
5. LOLBin 命令行例外判定
6. 未命中则进入本地 YARA，再进入云端

理由：
- 先走低成本高确定性路径，可显著减少云调用。
- 明确“拒绝规则”最高优先级，防止被盗证书和脆弱驱动绕过。

备选：允许规则优先于拒绝规则。
- 放弃原因：会导致被盗证书样本被误放行。

### 3) 数据源采用“本地文件 + 可索引存储 + TTL 缓存”三层

决策：
- 策略文件：`trusted_publishers.(yaml|json)`、`revoked_certs.json`、`vulnerable_drivers.json`、`lolbin_command_whitelist.yaml`。
- 哈希库：
  - NSRL 与企业基线支持离线导入到 SQLite/LMDB（可选 Bloom 预过滤）。
  - 关键字段：`sha256`、`source`、`product`、`publisher`、`updated_at`。
- 本地安全信誉缓存：LRU + TTL（默认 10 分钟），仅缓存“已验证安全”样本。

理由：
- 与当前代码的本地执行模型兼容，不依赖远端强一致存储。
- 可在端点离线状态下继续工作。

备选：全部在线查询中心库。
- 放弃原因：网络抖动会影响主流程时延与可用性。

### 4) 与当前代码的最优接入点

决策：
- 在 `Analyzer.executeSmart` 和 `Analyzer.executeDeep` 前置调用 `WhitelistEngine`：
  - `allow` -> 直接安全放行，跳过云端。
  - `deny` -> 直接高危，跳过后续。
  - `continue` -> 进入现有 YARA + 云端路径。
- `fast` 阶段先查缓存/权威哈希，减少不必要 MB/VT 请求。
- 在 `cmd/edr/main.go` 的记录构建处补齐上下文字段：
  - 文件：`signature_valid`、`signer_subject`、`certificate_thumbprint`。
  - 进程：`start_args`、`ppid`、`parent_name/parent_path`（若可得）。

理由：
- 最小侵入复用现有 `analyzer + cloud_multi + local matcher`，实现成本与回归风险最低。

备选：重写整个风险分析流水线。
- 放弃原因：风险高、周期长、收益不成比例。

### 5) LOLBin 采用“命令行级白名单”而非文件级白名单

决策：`powershell.exe/cmd.exe/wmic.exe/certutil.exe` 等仅在命令行模板命中允许策略时放行，否则继续 YARA/云分析。

理由：
- 双刃剑程序文件本身可信，但行为可恶意化。

备选：将 LOLBin 作为全局白名单。
- 放弃原因：会显著扩大攻击面。

### 6) 输出可解释性增强

决策：在结果中增加 `whitelist_analysis` 区块：
- `checked`、`decision`、`reason`、`policy_id`、`evidence`、`source`、`expires_at`。

理由：
- 支持审计、SOC 复盘、策略调优与误报治理。

## Risks / Trade-offs

- [策略库过期导致漏判/误判] → 增加版本号与更新时间，过期告警并支持热更新。
- [NSRL/企业基线体量大导致查询慢] → 采用 SQLite 索引 + Bloom 预过滤 + 批量导入。
- [命令行白名单过宽被滥用] → 强制精确匹配或受控通配符，并记录命中审计日志。
- [证书黑名单误命中] → 引入证据字段（thumbprint/serial/issuer）与人工复核开关。
- [跨平台字段缺失] → 字段缺失不阻塞流程，降级为 `continue` 并记录原因。

## Migration Plan

1. 新增 `WhitelistEngine` 接口与空实现（仅 `continue`），先不改变现网行为。
2. 接入缓存层与哈希库层（safe/malicious/NSRL/enterprise baseline）。
3. 接入签名发布者层、证书黑名单与 BYOVD 拒绝层。
4. 接入 LOLBin 命令行规则与上下文字段透传。
5. 扩展输出字段与测试（单测 + 回归 + 性能基线）。
6. 灰度启用：先告警不拦截，再逐步切换到强策略。

## Open Questions

- NSRL 数据导入格式与更新周期采用哪种企业标准（每日/每周）？
- BYOVD 列表是否直接对齐微软 Vulnerable Driver Blocklist，还是加企业自定义增量？
- 命令行白名单采用精确匹配、前缀匹配还是 DSL（并如何做风险边界）？
- 是否在 `risk analyze` CLI 中增加 `-whitelist-policy` 与 `-whitelist-cache-ttl` 参数？

## Conversation Addendum: Severity Fallback Decision

### Decision
When local YARA-X emits a match and metadata `severity` is absent/invalid/`<=0`, assign severity via fallback classifier before score aggregation.

### Rationale
Without fallback, dangerous matches can carry `severity=0`, pulling local score down and producing underestimation in fast/smart/deep outputs.

### Implementation Notes
- Fallback classifier tokenizes `rule_name` and `tags`.
- Family profiles provide high bands for strong malicious classes (for example webshell/ransomware).
- If no family profile is matched but a rule did match, use a non-zero default matched severity.
- Only truly empty signal stays at `0`.

### Compatibility
- No output schema change.
- Existing `yara_results[].severity` field remains the source of local-severity evidence.
- Behavior is backward-compatible but safer for missing-metadata rules.
