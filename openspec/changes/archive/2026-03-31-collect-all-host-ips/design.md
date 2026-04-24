## Context

现有主机信息采集会在多个内网地址场景下仅保留一个 `internalIp`，外网地址也只保留单值。这在虚拟网卡、容器网卡、VPN、多出口网络等环境中会损失关键上下文。与此同时，各扫描模式对主机 IP 字段的承载不一致，增加了消费端处理成本。

## Goals / Non-Goals

**Goals:**
- 在主机信息采集层完整收集全部内网与外网 IPv4 地址。
- 保持 `internalIp` / `externalIp` / `displayIp` 兼容，同时新增 `internalIpList` / `externalIpList`。
- 在 `process/account/user-group/file` 四类扫描输出中统一透传列表字段。
- 在 Excel 导出中增加对应列，便于运维直接核对。

**Non-Goals:**
- 不改变现有过滤参数语义（`ip` 模糊匹配逻辑保持不变）。
- 不引入公网探测服务或外部网络依赖来“反查”公网 IP。
- 不修改风险分析能力的评分逻辑。

## Decisions

1. 主机模型扩展  
   在 `HostInfo` 中新增 `InternalIPs` 与 `ExternalIPs`，保留单值字段作为首选地址。

2. 输出契约兼容扩展  
   各扫描结果新增 `internalIpList` / `externalIpList`，不删除原单值字段，避免破坏旧消费者。

3. 统一注入策略  
   继续在各扫描主流程中从 `processscan.GetHostInfo()` 注入主机字段，避免多处重复采集。

4. 文件扫描补齐主机 IP 字段  
   文件扫描此前仅有 `hostname`，本次补齐 `displayIp/internalIp/externalIp` 及列表字段，统一跨模式体验。

## Risks / Trade-offs

- [输出体积增加] -> 新增列表字段会增大 JSON/Excel 体积，但换来多网卡可观测性提升。
- [消费者字段适配成本] -> 通过保留单值字段降低迁移成本，列表字段增量可选使用。
- [网卡顺序导致主值选择差异] -> 通过列表字段提供完整上下文，单值仅作兼容展示。

## Migration Plan

- 第一步：扩展 `HostInfo` 与 IP 采集逻辑。
- 第二步：扩展各扫描结果结构与注入逻辑。
- 第三步：更新 Excel 导出列并执行回归测试。
- 第四步：重建 Windows/Linux dist 包并验证命令可用。

## Open Questions

- 后续是否需要引入“主地址优先级策略”（例如优先物理网卡）来稳定 `internalIp` 单值。
