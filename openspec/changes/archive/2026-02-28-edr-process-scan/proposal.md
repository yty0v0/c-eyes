## Why

需要一个本地可用的 EDR 进程信息扫描能力，用于在不依赖外部命令执行的情况下采集进程元数据并统一输出，满足安全排查与资产可视化的需求。

## What Changes

- 新增 CLI 子命令用于进程信息扫描，命令执行后直接输出扫描结果（标准化结构/JSON）。
- 在 Windows 与 Linux 上实现进程枚举与元数据采集，使用系统 API 或内核接口（如 Windows API、/proc），不通过命令行调用外部工具。
- 支持按主机/进程属性进行过滤（hostname/ip/name/path/pids/参数等），并按平台返回额外字段（version、description、package 信息等）。
- 统一输出字段，无法获取的结果返回 null。

## Capabilities

### New Capabilities
- `process-info-scan`: 通过 CLI 执行进程信息扫描，支持过滤条件与跨平台字段的规范化输出。

### Modified Capabilities
- （无）

## Impact

- 新增/修改 CLI 入口（`cmd/edr`）。
- 新增进程扫描与字段映射逻辑（Windows/Linux），可能引入系统相关依赖（如 `golang.org/x/sys`、Linux 包管理数据库读取库）。
- 需要新增文档与测试用例覆盖过滤逻辑与字段完整性。
