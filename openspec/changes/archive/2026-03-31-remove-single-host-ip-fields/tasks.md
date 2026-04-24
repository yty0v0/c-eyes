## 1. Data Model Refactor

- [x] 1.1 从 `process/account/user-group/file` 输出模型移除 `externalIp/internalIp` 单值字段
- [x] 1.2 统一保留 `externalIpList/internalIpList` 作为唯一内外网 IP 字段
- [x] 1.3 调整 `HostInfo` 与配置结构，删除单值字段并使用列表字段

## 2. Collection and Filter Logic

- [x] 2.1 更新主机 IP 采集逻辑，仅维护内外网列表与展示 IP
- [x] 2.2 更新四类扫描主机字段注入逻辑，移除单值赋值
- [x] 2.3 更新 `ip` 过滤匹配逻辑，改为基于 `displayIp + 列表 + 全量IP` 匹配

## 3. Export and Documentation

- [x] 3.1 更新 process/account/user-group/file Excel 导出列，移除单值 IP 列
- [x] 3.2 更新 `docs/user-group.md`、`docs/system-account.md`、`docs/processscan-desgin.md`、`docs/usage.md` 的字段与示例
- [x] 3.3 同步 OpenSpec 变更说明和能力 delta 规范

## 4. Verification and Packaging

- [x] 4.1 执行 `go test ./...` 全量验证
- [x] 4.2 重建 `dist-windows-amd64` 与 `dist-linux-amd64` 二进制
- [x] 4.3 验证 dist 输出中仅包含 IP 列表字段
