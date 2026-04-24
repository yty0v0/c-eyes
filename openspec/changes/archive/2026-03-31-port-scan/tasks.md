## 1. Setup

- [x] 1.1 新建 `internal/portscan` 模块骨架（`types.go`、`scan.go`、`filter.go`、`scan_linux.go`、`scan_windows.go`）。
- [x] 1.2 定义端口扫描核心数据结构与固定输出字段模型（含 `status` 取值约束）。
- [x] 1.3 在 CLI 层预留 `edr port-scan` 子命令入口和参数绑定结构。

## 2. Core Implementation

- [x] 2.1 实现扫描主流程：模式选择、数据采集、字段补齐、过滤、结果组装。
- [x] 2.2 实现扫描模式策略（`tcp-connect` 默认、`tcp-syn` 可选）与统一调用接口。
- [x] 2.3 实现过滤逻辑（`groups`、`hostname`、`ip`、`proto`、`port`、`bindIp`、`processName`）。
- [x] 2.4 实现跨平台统一状态映射与空值兜底策略（字段不缺失）。

## 3. Linux Platform

- [x] 3.1 基于 Linux 系统数据源实现端口与协议信息采集（不调用外部命令）。
- [x] 3.2 实现端口到进程（`pid`/`processName`）与绑定地址（`bindIp`）映射。
- [x] 3.3 完成 Linux 场景下不可用字段兜底，保证输出契约一致。

## 4. Windows Platform

- [x] 4.1 基于 Windows 系统 API 实现端口、协议与进程映射采集（不调用外部命令）。
- [x] 4.2 实现绑定地址、内外网信息关联与 `status` 映射。
- [x] 4.3 完成 Windows 场景下字段兜底，保证与 Linux 输出结构对齐。

## 5. CLI & Output

- [x] 5.1 完成 `edr port-scan` 参数解析与校验（含扫描模式默认值与合法值检查）。
- [x] 5.2 接入统一输出管线，支持 `-output json|excel` 两种导出格式。
- [x] 5.3 新增 Excel 列映射与表头定义，覆盖全部返回字段并固定列顺序。
- [x] 5.4 更新帮助文本与使用示例，明确“仅信息收集，不做风险分析”。

## 6. Tests & Verification

- [x] 6.1 为过滤逻辑和扫描模式选择补充单元测试（默认模式、显式模式、参数组合）。
- [x] 6.2 为 Linux/Windows 采集层补充可注入依赖的测试与平台差异断言。
- [x] 6.3 增加 JSON/Excel 输出结构测试，验证字段完整性与列顺序稳定。
- [x] 6.4 执行回归测试并修复问题，确认变更不影响现有扫描能力。
