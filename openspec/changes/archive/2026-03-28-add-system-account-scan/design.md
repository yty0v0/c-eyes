## Context

当前代码库已有 `processscan` 与 `filescan` 两套扫描能力，具备跨平台采集、统一过滤与 JSON 输出的实现模式，但缺少“系统账号信息采集”能力。`docs/system-account.md` 已定义请求参数、返回字段和示例输出，同时明确要求“仅做信息收集，不做风险分析，且不得通过命令行采集”。本设计需要在保持现有 CLI 风格与代码组织方式的前提下，新增一条可独立演进的账号扫描链路，并保证 Linux 与 Windows 字段行为一致且可测试。

## Goals / Non-Goals

**Goals:**
- 提供 `edr account scan` 命令，输出结构为 `{"total": number, "rows": []}`。
- 新增 `internal/accountscan` 模块，按“采集 -> 主机信息补充 -> 过滤 -> 输出规范化”流程实现。
- Linux 通过系统文件解析采集账号信息；Windows 通过系统 API 采集账号信息；全程不依赖外部命令执行。
- 支持文档定义的过滤参数：`groups`、`hostname`、`ip`、`status`、`name`、`home`、`lastLoginTime`、`gid`、`uid`。
- 结果字段覆盖 `docs/system-account.md` 定义，平台不支持字段返回 `null` 或空列表，不因单字段失败中断全量扫描。

**Non-Goals:**
- 不新增账号风险判断、异常评分、威胁告警等分析逻辑。
- 不实现远程主机采集、集中任务编排或多主机聚合查询。
- 不实现域控/LDAP/AD 深度联动（仅处理本机可访问的系统账号信息）。
- 不在本次变更中引入新的外部网络依赖。

## Decisions

- **模块拆分与复用策略**
  - 新增 `internal/accountscan`，保持与 `processscan` 类似的入口形式：
    - `types.go`：参数与结果结构体。
    - `scan.go`：总流程编排。
    - `filter.go`：筛选逻辑。
    - `scan_linux.go` / `scan_windows.go`：平台采集实现。
  - 主机维度字段（`displayIp/externalIp/internalIp/bizGroup*`）复用现有 `processscan.GetHostInfo()` 输出模型，减少重复实现与行为漂移。

- **采集实现方式（禁止命令行）**
  - Linux：
    - `/etc/passwd`：`name/uid/gid/home/shell/comment`。
    - `/etc/group`：账号附属组 `groups`。
    - `/etc/shadow`：密码策略与过期字段（`pwdMaxDays/pwdMinDays/pwdWarnDays/passwordInactiveDays/expireTime/lastChangPwdTime/status`）。
    - `~/.ssh` 与 `authorized_keys`：`sshAcl/authorizedKeys`（含 key 类型、comment、value、md5）。
    - `/etc/sudoers` 与 `/etc/sudoers.d`：`sudo/sudoAccesses`。
    - 登录信息优先使用系统登录记录文件解析（如 `lastlog`），不可用时字段置空。
  - Windows：
    - 使用系统账户管理 API（如 NetAPI 系列）枚举本地账户并读取属性（`name/fullName/description/type/status/lastLoginTime/lastChangPwdTime` 等）。
    - 组信息使用系统 API 读取本地组/全局组成员关系。
    - 统一输出 `uid/gid` 数值表示时，对 SID 做稳定映射（与现有 processscan 的 Windows 风格保持一致）。

- **过滤与匹配规则**
  - `hostname/ip/home` 为大小写不敏感模糊匹配（子串匹配）。
  - `groups/status` 为数组“命中任一”匹配。
  - `uid/gid/name` 为精确匹配。
  - `lastLoginTime` 采用闭区间时间范围匹配（`from <= t <= to`），输入解析支持 RFC3339 和 `YYYY-MM-DD`。

- **输出与兼容策略**
  - 顶层输出固定为对象：`total` + `rows`。
  - 行级字段固定完整输出；无法采集或平台不支持时返回 `null`（切片字段可为空切片），保证消费端字段稳定性。
  - Linux/Windows 状态值存在枚举差异，内部保留平台语义并在文档约定字段中统一输出。

- **可测试性设计**
  - 将文件解析与系统 API 调用封装为可注入依赖，便于在非目标平台做单测。
  - 为关键解析器（passwd/shadow/group/authorized_keys/sudoers）提供 fixture 测试。
  - 为过滤器提供独立表驱动测试，覆盖组合条件。

## Risks / Trade-offs

- [Linux 登录记录格式在发行版间差异较大] → 采用“尽力解析 + 失败降级为 null”策略，并补充单测覆盖常见格式。
- [读取 shadow/sudoers 可能受权限限制] → 对受限字段返回 null，不影响其他字段采集。
- [Windows 账号类型与状态映射存在版本差异] → 在代码中集中维护映射表并保留原始值兜底路径。
- [字段多且跨平台差异大，易出现输出不一致] → 统一结果构造器，所有平台通过同一规范化出口编码。
- [authorized_keys 可能非常大] → 限制单账号解析条目数并允许配置上限，防止异常文件拖垮扫描。

## Migration Plan

- 第一步：新增 `internal/accountscan` 基础结构与 CLI 入口，不影响现有命令。
- 第二步：实现 Linux/Windows 采集与过滤，补齐 JSON 输出。
- 第三步：补充测试、文档与示例，确保 `go test ./...` 通过。
- 回滚策略：若新命令出现问题，可通过回退本次变更移除 `account` 子命令，不影响已有 `process/file/risk` 功能。

## Open Questions

- `groups` 请求参数的业务语义是否最终确认为“业务组 ID”还是“账号所属系统组 ID”。
- Windows `status` 过滤是否需要支持“锁定（1）”作为输入枚举（文档请求与返回定义存在差异）。
- Linux `lastLoginTime` 数据源在极简系统中不可用时，是否接受统一返回 `null` 而非额外推断。
