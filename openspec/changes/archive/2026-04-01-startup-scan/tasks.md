## 1. Setup

- [x] 1.1 新建 `internal/startupscan` 模块骨架（`types.go`、`scan.go`、`filter.go`、`scan_linux.go`、`scan_windows.go`）。
- [x] 1.2 定义启动项扫描请求参数结构与统一输出记录结构，覆盖全部契约字段。
- [x] 1.3 在 CLI 层新增 `edr startup-scan` 子命令入口与参数绑定。

## 2. Core Implementation

- [x] 2.1 实现启动项扫描主流程：平台采集、主机元数据注入、过滤、结果组装。
- [x] 2.2 实现过滤逻辑（`groups`、`hostname`、`ip`、`name`、`initLevel`、`defaultOpen`、`isXinetd`、`showName`、`user`、`enable`、`startType`、`publisher`）。
- [x] 2.3 实现字段完整性与空值兜底策略，保证跨平台字段键不缺失。

## 3. Linux Implementation

- [x] 3.1 基于 Linux 系统数据源实现启动项采集（不调用外部命令），覆盖运行级别与默认启用状态。
- [x] 3.2 实现 `xinetd` 与 `rc0-rc7` 状态映射逻辑，并写入统一输出字段。
- [x] 3.3 完成 Linux 下 Windows 专属字段的空值兜底与一致性校验。

## 4. Windows Implementation

- [x] 4.1 基于 Windows 系统 API 实现启动项/服务信息采集（不调用外部命令）。
- [x] 4.2 实现 `showName`、`user`、`enable`、`startType`、`publisher` 字段映射。
- [x] 4.3 完成 Windows 下 Linux 专属字段的空值兜底与一致性校验。

## 5. CLI & Output

- [x] 5.1 完成 `edr startup-scan` 参数解析、合法值校验与帮助文本更新。
- [x] 5.2 接入统一输出管线，支持 `-output json|excel`。
- [x] 5.3 新增启动项扫描 Excel 表头与字段映射，固定列顺序并覆盖全部返回字段。

## 6. Tests & Verification

- [x] 6.1 为参数过滤逻辑补充表驱动单测（模糊匹配、数组匹配、布尔匹配）。
- [x] 6.2 为 Linux/Windows 采集层补充可注入依赖测试，验证平台字段映射与空值策略。
- [x] 6.3 增加 JSON/Excel 输出结构测试，验证字段完整性与列顺序稳定。
- [x] 6.4 执行回归测试并确认该能力仅输出信息收集结果，不引入风险分析字段。
