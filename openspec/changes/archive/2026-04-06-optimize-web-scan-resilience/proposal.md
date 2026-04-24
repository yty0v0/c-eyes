## Why

在复杂部署场景中，Web 资产采集仍存在鲁棒性风险：配置 include 链可能未完全解析、软链接路径可能导致去重偏差、运行态与静态态区分不清。需要进一步增强扫描韧性与结果解释性。

## What Changes

- 为 `web-application-scan` 与 `web-site-scan` 增加 include 递归解析能力（带深度限制）。
- 增加配置路径软链接真实路径解析，减少同一站点重复识别。
- 在两类结果中新增 `isRunning` 字段，标记运行态关联是否命中。
- 补充非常规参数与相对路径场景测试，增强对抗回归能力。
- 同步更新 Excel 导出字段头与 dist 产物。

## Capabilities

### New Capabilities
- None.

### Modified Capabilities
- `web-application-scan`: 增强 include 解析、软链接路径处理与运行状态标记。
- `web-site-scan`: 增强 include 解析、软链接路径处理与运行状态标记。

## Impact

- 受影响模块：`internal/webapplicationscan`、`internal/websitescan`、`cmd/edr` Excel 导出层。
- 结果影响：输出字段新增 `isRunning`，并提升非常规部署发现率与稳定性。
