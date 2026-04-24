## Context

需要在不调用外部命令的前提下实现跨平台进程信息扫描。当前仓库几乎为空，需要从零搭建 CLI 入口与进程采集逻辑。输出字段覆盖主机信息、进程元数据、平台特有字段（Windows/Linux）以及可选的业务标签类字段；无法获取时需输出 null。

## Goals / Non-Goals

**Goals:**
- 提供 `edr` CLI 进程扫描能力，执行后直接输出结果（建议 JSON）。
- Windows/Linux 使用系统 API 或内核接口采集进程信息，不通过命令行调用外部工具。
- 支持模糊过滤（hostname/ip/name/path/startArgs 等）与精确过滤（pid、root、types 等）。
- 输出字段与需求保持一致，平台不支持的字段返回 null。

**Non-Goals:**
- 不实现远程主机扫描或分布式采集。
- 不实现进程杀死/控制等主动防护能力。
- 不做复杂的资产/业务分组管理系统（仅保留字段，值可为空或由可选配置提供）。

## Decisions

- **采集方式**：
  - Linux 通过读取 `/proc` 解析 `stat`/`status`/`cmdline`/`exe` 等，获取 pid、ppid、startTime、uid/gid、路径、启动参数等。
  - Windows 使用 `Toolhelp32Snapshot` / `QueryFullProcessImageName` / `GetProcessTimes` / `GetProcessInformation` 等 API 获取进程元数据；版本与描述通过 `VersionInfo` 读取文件信息。
  - 通过 `golang.org/x/sys/windows` 与标准库实现系统调用，避免外部命令。

- **过滤策略**：
  - “模糊查询”统一为大小写不敏感的子串匹配。
  - `pids`/`types` 等数组参数采用“包含任一即匹配”。
  - `startTime` 过滤为“进程启动时间 >= 给定时间”。

- **输出策略**：
  - 输出为 JSON 数组，字段完整；无法获取的字段置为 `null`。
  - 平台不支持字段固定返回 `null`。

- **包信息（Linux）**：
  - 优先读取包管理数据库（`dpkg`/`rpm`）而非执行命令：
    - Debian 系列解析 `/var/lib/dpkg/status` 与 `info/*.list`。
    - RPM 系列使用 rpmdb 读取库（如 `go-rpmdb`）。
  - 无法识别时 `packageName/packageVersion/installByPm` 返回 `null`。

- **主机/业务字段**：
  - `displayIp/externalIp/internalIp/bizGroup*` 等主机侧字段先通过本机网卡与可选配置获取；无配置则返回 `null`。

## Risks / Trade-offs

- [权限不足导致信息缺失] → 对受限字段返回 `null`，并记录日志以便诊断。
- [读取 /proc 在高进程数下性能开销] → 采用流式遍历与字段惰性解析，避免多次扫描。
- [包管理数据库差异] → 先支持主流 dpkg/rpm，其他发行版字段返回 `null`。
- [Windows 字段不易判定类型] → 以是否存在可见窗口/是否系统进程等启发式判定，结果允许为空或回退为后台类型。

## Migration Plan

- 新增 CLI 命令与进程扫描模块。
- 添加单元测试与平台分支测试。
- 无数据迁移需求，发布后即可使用。

## Open Questions

- “进程类型”1/2/3 的精确定义是否需要业务侧确认？
- `externalIp` 是否需要访问外部服务获取？如果不允许网络访问，是否直接返回 null？
- 是否需要提供配置文件以填充 `bizGroup`、`hostTagList` 等业务字段？
