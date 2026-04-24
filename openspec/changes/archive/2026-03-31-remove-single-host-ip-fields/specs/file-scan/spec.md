## MODIFIED Requirements

### Requirement: 输出字段与结果格式
系统 SHALL 以 JSON/Excel 输出统一结构，包含扫描元信息与扩展采集字段：

- 顶层扫描元信息：`scan_mode`, `source`, `hostname`, `displayIp`, `externalIpList`, `internalIpList`。
- `basic_info`：`file_path`, `file_name`, `file_size_bytes`, `creation_time`, `modification_time`, `access_time`（RFC3339，毫秒精度），以及平台差异字段（Windows: `attributes`；Linux: `owner`, `group`, `mode`）。
- `hashes`：`sha256`, `imphash`。
- `signature`（Windows 可用）：`is_signed`, `signature_valid`, `signer_subject`, `certificate_thumbprint`。
- `binary_info`（仅 PE/ELF 可执行文件）：`magic_bytes`, `imported_libraries`, `sections_info`, `version_info`。
- `context`（Windows 可用）：`motw_zone_id`, `download_url`。

#### Scenario: 字段缺失处理
- **WHEN** 某字段不可获取或不适用
- **THEN** 对应字段在 JSON 中输出为 `null`；`externalIpList/internalIpList` 在无数据时输出空数组
