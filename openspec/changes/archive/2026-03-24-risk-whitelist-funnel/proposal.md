## Why

当前风险分析已支持 `fast/smart/deep` 分阶段与本地/云端融合，但白名单判定仍过于单一（主要依赖 `signature_valid=true`），容易被被盗证书、BYOVD 驱动、以及 LOLBin 滥用绕过。需要建立“低成本优先、强证据优先、可解释可审计”的多维白名单漏斗，减少不必要的云端调用并降低误放行风险。

## What Changes

- 引入多维白名单策略引擎（Whitelist Engine），统一执行“允许/拒绝/继续分析”判定。
- 白名单策略升级为四个维度并设定强优先级：
  - 证书与签名信任（Trusted Publisher + Revoked/Stolen Cert + BYOVD Blocklist）
  - 强哈希与信誉（NSRL、企业基线、本地安全缓存）
  - 路径与上下文组合（系统路径+签名、业务路径+进程树）
  - 行为级灰名单例外（LOLBin 按命令行白名单，不做文件级免检）
- 定义白名单漏斗：
  1. 本地缓存命中（safe/malicious）
  2. 权威哈希库命中（NSRL/企业基线）
  3. 签名与发布者校验（含证书撤销/泄露校验）
  4. 若未命中或属于灰名单例外，进入本地 YARA-X
- 将白名单判定接入 `smart` / `deep` 前置阶段，`fast` 阶段可复用缓存/哈希层以降低云调用。
- 增加白名单审计输出字段，记录命中来源、规则 ID、证据（可脱敏）。
- 增加配置与数据文件规范：可信发布者列表、证书黑名单、BYOVD 列表、企业基线哈希、LOLBin 命令行白名单。

## Capabilities

### New Capabilities
- `risk-whitelist-policy`: 多维白名单与灰名单策略引擎、策略漏斗执行、审计输出与配置管理。

### Modified Capabilities
- `risk-analysis`: 分析流程新增白名单漏斗前置判定，模式行为（fast/smart/deep）与输出结构发生规范级变更。

## Impact

- 主要影响模块：
  - `internal/riskanalysis/analyzer.go`（在 smart/deep 前加入白名单漏斗）
  - `internal/riskanalysis/types.go`（增加 whitelist verdict/audit 结构）
  - `cmd/edr/main.go`（补充风险记录所需上下文字段，如签名发布者、进程命令行/父进程信息）
  - `internal/processscan/*`、`internal/filescan/*`（增强上游字段透传）
- 新增本地策略数据源（JSON/YAML + 可选 SQLite/Bloom 索引）和热加载能力。
- 云端查询量预期显著下降（大量安全样本在本地漏斗提前放行）。

## Conversation Addendum: Local YARA Severity Fallback

Recent implementation updates from discussion are now tracked in this change:

- Added severity fallback policy for local YARA matches where metadata `severity` is missing/invalid/zero.
- Fallback uses rule-name/tag families to avoid severe malware matches being scored as zero by default.
- Known families (for example webshell/ransomware classes) map to high fallback bands.
- Unclassified but matched rules use a non-zero default matched severity.
- Corresponding tests were added to lock behavior and prevent regression.

This addendum aligns OpenSpec with the current implementation in:
- `internal/riskanalysis/severity_fallback.go`
- `internal/riskanalysis/yarax_cgo.go`
- `internal/riskanalysis/severity_fallback_test.go`
