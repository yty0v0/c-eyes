## Why

当前缺少统一的 Web 站点信息采集能力，导致 Windows 与 Linux 的站点资产无法以一致结构输出，也无法满足批量检索与导出场景。需要尽快补齐该能力，以支撑资产盘点与后续联动模块的数据输入。

## What Changes

- 新增 `edr web-site-scan` 能力，面向 Windows 和 Linux 采集站点信息。
- 明确采集约束：仅做信息收集，不做风险分析，且采集阶段禁止通过外部命令行工具获取数据。
- 增加查询过滤参数：`groups`、`hostname`、`ip`、`port`、`proto`、`type`、`rootPath`。
- 定义站点输出字段与嵌套对象（`domains`、`virtualDir`、`root`），并统一跨平台语义。
- 支持 JSON 与 Excel 两种输出格式，CLI 提示信息使用中文，文本编码使用 UTF-8。
- 将内/外网 IP 采集改为数组形式（保留展示字段 `displayIp`，移除单值存储依赖）。

## Capabilities

### New Capabilities
- `web-site-scan`: 提供跨平台 Web 站点信息采集、过滤与 JSON/Excel 导出能力，并规范输出契约。

### Modified Capabilities
- None.

## Impact

- 受影响模块：CLI 命令入口、站点采集服务、结果序列化与导出模块（Excel/JSON）。
- 受影响系统：Windows（IIS/nginx/weblogic/websphere/jetty/wildfly 等）与 Linux（nginx/tomcat/weblogic/jboss/wildfly/jetty 等）站点信息采集路径。
- 对外契约：新增 `web-site-scan` 输出模型，IP 字段调整为数组化表示。
