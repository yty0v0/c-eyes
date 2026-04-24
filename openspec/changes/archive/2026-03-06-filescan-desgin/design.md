## Context

当前系统仅提供进程信息扫描能力（`edr process scan`），缺少文件扫描与智能扫描能力。新增文件扫描需要覆盖三种模式，并满足低资源消耗下的高危路径与近期威胁覆盖，同时与现有 CLI 输出（JSON/Excel）保持一致。

## Goals / Non-Goals

**Goals:**
- 提供全盘扫描、指定路径扫描、智能扫描三种模式。
- 实现智能扫描管线：目标收集 -> 过滤引擎 -> 深度扫描 -> 结果上报。
- 引入本地缓存（SQLite）与云端信誉查询的短路机制。
- 支持系统空闲/行为驱动触发，并可暂停/恢复扫描。
- 结果输出支持 JSON 与 Excel。

**Non-Goals:**
- 不实现完整的商业杀毒引擎，仅提供可插拔的深度扫描接口。
- 不实现云端信誉服务本身，仅提供客户端接口与默认空实现。
- 不实现内核驱动（Minifilter）本体，仅提供本地接口接入点。

## Decisions

1. 新增 `internal/filescan` 模块，提供 `Scan(ctx, params)` 入口与 `ScanMode`/`ScanTask`/`FileScanResult` 数据结构，便于 CLI 直接调用。
2. 智能扫描采用管线式编排：Target Collector 只生成高风险目标列表，避免全量遍历；Filter Engine 严格按“本地缓存 -> 信任签名 -> 云端信誉”顺序短路；Deep Scanner 仅处理“灰文件”。
3. 本地缓存使用 SQLite（纯 Go 驱动，如 `github.com/glebarez/sqlite`），表结构采用 `ScanCache`（file_path, file_hash, last_modified, scan_result, last_scan_time），并以 `file_path + last_modified` 做一致性判断。
4. 签名校验抽象为 `SignatureVerifier` 接口：Windows 使用 Authenticode 校验；非 Windows 返回未知并继续后续流程。
5. 云端信誉抽象为 `ReputationClient` 接口，支持批量异步查询并限制并发；默认实现返回 UNKNOWN 以避免阻塞。
6. 深度扫描抽象为 `DeepScanner` 接口：优先对接 YARA/本地规则引擎；无可用引擎时返回 UNKNOWN。Windows 下设置低优先级线程并尝试 I/O 限制；Linux 下使用 `setpriority` 降低优先级。
7. 结果上报由 `ResultReporter` 统一写入缓存并生成输出；CLI 侧复用 Excel 写入逻辑，新增文件扫描专用表头。
8. 智能扫描调度器提供 `IdleTrigger` 与 `EventTrigger`，支持 `Pause()/Resume()` 控制；若平台无法可靠获取空闲状态，则仅启用行为驱动触发。

## Risks / Trade-offs

- [平台差异导致空闲检测不可靠] -> 采用接口抽象与平台能力探测，无法支持时仅启用行为触发。
- [云端信誉不可用导致扫描压力增加] -> 默认 UNKNOWN 并进入深度扫描，限制并发与节流。
- [SQLite 并发写入产生锁等待] -> 使用单写入协程或事务批量写入。
- [深度扫描依赖外部规则库] -> 以可插拔接口隔离，并提供空实现保证可运行。

## Migration Plan

- 新增文件扫描命令与模块代码，不影响现有进程扫描流程。
- 首次运行时创建本地缓存数据库与表结构。
- 回滚仅需移除新命令与模块，不影响既有数据。

## Open Questions

- 云端信誉查询的配置入口（地址/鉴权/超时）放在哪里？
- YARA 规则或本地规则库的分发与更新策略如何设计？
- Minifilter 推送事件的接口协议如何定义？
- 本地缓存数据库路径是否可配置（默认用户目录/工作目录）？
