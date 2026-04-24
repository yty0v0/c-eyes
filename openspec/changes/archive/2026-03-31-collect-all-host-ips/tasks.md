## 1. Host IP Collection

- [x] 1.1 扩展 `HostInfo`，新增 `InternalIPs` 与 `ExternalIPs`
- [x] 1.2 调整 `collectIPs` 逻辑，采集全部内外网 IPv4，并保留单值兼容字段
- [x] 1.3 处理配置覆盖与列表合并，保证覆盖值不会丢失于列表

## 2. Scan Output Models

- [x] 2.1 在 `process` 输出模型中新增 `internalIpList` / `externalIpList`
- [x] 2.2 在 `account` 输出模型中新增 `internalIpList` / `externalIpList`
- [x] 2.3 在 `user-group` 输出模型中新增 `internalIpList` / `externalIpList`
- [x] 2.4 在 `file` 输出模型中补齐主机 IP 单值字段与列表字段

## 3. Host Metadata Injection

- [x] 3.1 更新 `process` 主机字段注入逻辑，透传列表字段
- [x] 3.2 更新 `account` 主机字段注入逻辑，透传列表字段
- [x] 3.3 更新 `user-group` 主机字段注入逻辑，透传列表字段
- [x] 3.4 更新 `file` 过滤/基础结果构造逻辑，透传主机字段与列表字段

## 4. Excel Export

- [x] 4.1 更新进程 Excel 导出列，新增 `internalIpList` / `externalIpList`
- [x] 4.2 更新账号 Excel 导出列，新增 `internalIpList` / `externalIpList`
- [x] 4.3 更新用户组 Excel 导出列，新增 `internalIpList` / `externalIpList`
- [x] 4.4 更新文件扫描 Excel 导出列，新增主机 IP 字段与列表列

## 5. Verification & Packaging

- [x] 5.1 执行 `go test ./...`，验证回归通过
- [x] 5.2 运行四类扫描命令，确认列表字段输出
- [x] 5.3 重建 `dist-windows-amd64` 与 `dist-linux-amd64` 二进制并验证 `--help`
