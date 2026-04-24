## Why

当前 Web 应用与 Web 站点采集主要依赖静态默认配置路径，遇到非常规部署路径或运行态配置参数时，容易出现漏采或元数据不完整。需要补充动态进程关联能力，提高跨平台发现率与结果可信度。

## What Changes

- 为 `web-application-scan` 增加进程关联增强：从运行进程中识别服务类型、提取配置路径并补全静态解析结果。
- 为 `web-site-scan` 增加进程关联增强：补充 `pid`、`cmd`、`user` 等运行态字段，并支持从进程参数发现非常规配置路径后解析。
- 保持信息收集边界：不引入风险分析字段，不调用外部命令行工具。
- 新增回归测试：动态关联单测、golden 回归、Windows/Linux 准确性覆盖。
- 更新发布产物：刷新 `dist-windows-amd64/edr.exe` 与 `dist-linux-amd64/edr`。

## Capabilities

### New Capabilities
- None.

### Modified Capabilities
- `web-application-scan`: 增强运行进程关联与配置路径发现能力。
- `web-site-scan`: 增强运行进程关联能力并补全运行态字段。

## Impact

- 受影响代码：`internal/webapplicationscan/*`、`internal/websitescan/*`、`cmd/edr/*web_site*`。
- 受影响行为：站点/应用发现不再仅限默认路径，结果字段完整性提升。
- 受影响测试：新增动态关联与 golden 回归测试，现有接口保持兼容。
