## Context

`benchmark` 模块已经完成去脚本化重构，但最近围绕四套模板的深测暴露出一个更细的约束：仅仅“有原生路径”还不够，原生结果本身还必须可信。当前实现已经把 Windows / Linux / EulerOS / Kylin 的基线事实采集迁移到 Go 原生路径，但 OpenSpec 还没有明确记录以下边界：

- 四套模板、四个基线级别都不得再通过命令执行补采事实。
- Windows 安全策略类字段必须优先使用可信的原生安全接口，而不是把本可判定值误降级为 `unknown`。
- 当原生来源确实不足时，只能显式返回 `unknown`，不能重新引入命令回退。

最近一次 Windows 管理员实测说明这个边界是必要的：`PasswordComplexity`、`AllowAdministratorLockout`、`ClearTextPassword` 最初并不是“系统无法提供”，而是 `SamConnect` 请求权限过低，导致后续 `SamOpenDomain`/`SamQueryInformationDomain` 不能稳定给出值。修复后，这些字段能够通过 SAM/LSA/NetAPI 原生链路直接返回确定结果，并与平台策略导出结果一致。

## Goals / Non-Goals

**Goals:**
- 把 benchmark 原生采集的约束从“架构方向”提升为明确的规范要求。
- 明确四套模板、四个基线级别都必须遵守 native-only 采集边界。
- 明确“可信优先”原则：能可靠原生判定的字段必须返回真实值，不得因实现缺陷退化为 `unknown`。
- 记录 Windows 安全策略类检查的原生来源模型，避免未来再次误用权限或 API。

**Non-Goals:**
- 不重新引入任何脚本、shell、`os/exec` 或 vendor baseline 工具作为运行时兜底。
- 不要求每个内部字段都必须暴露给终端用户。
- 不把维护时的对照验证命令变成运行时依赖。

## Decisions

### Decision 1: `benchmark-scan` 规范要显式覆盖 all-template, all-level native-only contract
- Decision: 将 `benchmark-scan` 规范改为明确约束 `windows`、`linux`、`euleros`、`kylin` 四套模板和全部支持级别都必须使用原生采集。
- Rationale: 之前规范虽然写了 native collectors，但没有把“四模板四级别无命令回退”讲透，后续维护者仍可能在某个模板或级别里恢复命令采集。
- Alternative considered: 只在设计说明里保留“倾向原生”。Rejected，因为这无法形成可测试、可归档的约束。

### Decision 2: 原生可信性是规范要求，不只是实现质量
- Decision: 新增要求，凡是操作系统存在足够可信的原生来源，benchmark 必须返回可判定值，不能因为访问权限、错误 access mask、或错误 API 选择而把结果落成 `unknown`。
- Rationale: 这次 Windows 密码策略字段问题说明，不少 `unknown` 其实不是平台限制，而是 collector 缺陷。这个边界必须进入 spec，后续回归测试才有明确依据。
- Alternative considered: 将这类问题视为普通 bug，不纳入 spec。Rejected，因为它直接影响检查结论可信度，属于用户可见行为。

### Decision 3: “没有可信原生来源” 与 “实现没取到” 必须区分
- Decision: 只有当当前平台确实不存在足够可信的原生来源时，benchmark 才能返回 `unknown`；否则应继续修正 native collector，而不是命令补值或接受不确定结果。
- Rationale: 这样才能避免两类错误行为：
  - 用命令回退掩盖 native collector 缺陷；
  - 把本应可判定的策略长期留在 `unknown`。
- Alternative considered: 允许维护者在个别字段上回退到命令采集。Rejected，因为这会重新破坏“运行时无命令依赖”的统一约束。

### Decision 4: Windows 安全策略字段按来源分层，而不是一个全局成败开关
- Decision: 设计上继续采用分区加载和按来源取值的方式，例如 system access、event audit、privilege rights 分别缓存和求值。
- Rationale: 某一个安全策略分支短暂失败，不应让整个 Windows 安全策略集合一起失效；这种分层也更适合定位“原生来源不存在”还是“实现请求错误”。
- Alternative considered: 单次整体加载全部安全策略并失败即全失败。Rejected，因为这会把局部问题放大成大量 `unknown`。

## Risks / Trade-offs

- [Risk] Linux / EulerOS / Kylin 某些历史规则仍可能残留“原脚本语义”而不是“结构化原生语义”。
  -> Mitigation: 继续把规则对应的事实来源逐项收敛到文件/API 级采集，并以模板级深测覆盖四个级别。

- [Risk] Windows 安全策略字段对不同版本 SKU、权限模型、域环境的兼容性仍可能有差异。
  -> Mitigation: 保留 live native tests 和管理员实机回归，对关键字段做原生结果与系统真值对照。

- [Risk] “可信原生来源” 的定义过宽会导致后续实现争议。
  -> Mitigation: 在实现层优先选择操作系统正式 API、本机配置文件、受支持 registry/LSA/SAM 读取路径，并把不可判定情况显式落为 `unknown`。

## Migration Plan

1. 用本 change 的 spec delta 把 `benchmark-scan` 的 native-only 与 trustworthiness 约束固化下来。
2. 后续归档时把 delta 同步进 `openspec/specs/benchmark-scan/spec.md`。
3. 继续以四模板四级别实测维持回归基线，必要时补充更多 live/native tests。
4. 维护侧 Linux-family 实机对照记录集中放在 `validation.md`，明确哪些模板已完成实机比对，哪些仍待 EulerOS/Kylin 主机执行。

## Open Questions

- Linux / EulerOS / Kylin 是否还存在少量“命令启动但非脚本回放”的 collector 残留，需要在后续 change 中继续彻底清零。
- 是否需要把“原生结果对照系统真值”的验证要求进一步细化到 benchmark 模块的测试规范中。
