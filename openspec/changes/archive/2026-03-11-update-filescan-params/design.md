## Context

当前文件扫描输出字段仅包含基础路径/哈希/扫描结果等少量信息，难以满足威胁情报碰撞、签名可信度判断与二进制启发式分析的需要。`filescan-desgin1.md` 明确新增了基础元数据、密码学指纹、签名信息、二进制内部特征与上下文标记等采集要求，因此需要扩展文件扫描结果的数据模型与输出格式（JSON/Excel）。

## Goals / Non-Goals

**Goals:**
- 扩展文件扫描输出结构，覆盖基础元数据、哈希、签名、二进制特征与上下文信息。
- 明确平台差异字段（Windows 属性 / Linux Owner/Group/Mode），不可获取时输出 `null`/空值。
- 统一 JSON 与 Excel 的字段映射方式，保证可测试与可解析。

**Non-Goals:**
- 不改变扫描模式（full/path/smart）与扫描管线的执行顺序。
- 不调整 `ScanCache` 数据模型与缓存策略。
- 不新增威胁检测逻辑或云端信誉策略。

## Decisions

- **输出结构采用分组 JSON + 扫描元信息顶层字段**：JSON 以 `basic_info`、`hashes`、`signature`、`binary_info`（PE/ELF）、`context` 为核心分组，同时保留扫描元信息字段（`scan_mode`、`source`、`hostname`）在顶层，便于下游快速索引扫描结论。`scan_result`、`last_scan_time` 仅用于内部缓存与流程控制，不作为对外输出字段。备选方案是将扫描字段放入 `scan` 分组，但会增加既有消费侧改造成本。
- **字段命名统一为 snake_case**：与 `filescan-desgin1.md` 的示例保持一致，降低跨语言结构体映射成本。现有 camelCase 字段将作为兼容性问题在迁移计划中说明。
- **Excel 输出采用扁平化列名**：使用 `group.field` 形式（如 `basic_info.file_path`、`hashes.sha256`、`binary_info.sections_info`），保证列名与 JSON 分组一致，同时易于人类阅读与脚本解析。
- **数据采集分层**：
  - 基础元数据与 `sha256` 始终采集。
  - `imphash`、`binary_info` 仅对可执行文件（PE/ELF）采集；无法解析时置 `null`。
  - 签名信息与 MOTW 仅在 Windows 可用；Linux 输出 `null`。

## Risks / Trade-offs

- **[性能开销]** 增加哈希计算与二进制解析带来 CPU/IO 开销 → 通过只对可执行文件采集深度字段、复用已有读取缓冲来缓解。
- **[兼容性]** 输出字段命名与结构变化会影响下游解析 → 在迁移计划中明确更新点，并同步更新文档/示例。
- **[平台差异]** A-Time、签名与 MOTW 在不同系统可用性差 → 统一使用 `null`/空值表示缺失。

## Migration Plan

1. 更新文件扫描输出结构与 Excel 列头映射。
2. 更新文档与示例（JSON/Excel 结构）。
3. 若存在下游消费方，通知字段变更并提供映射表。

## Open Questions

- 是否需要为旧字段提供兼容输出（例如保留旧字段名 `hashSha256`）？当前默认不保留。
