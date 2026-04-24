## MODIFIED Requirements

### Requirement: CLI 支持文件扫描
系统 SHALL 在 `edr filescan` 命令下提供本地文件扫描能力，支持 `--scan-mode` 本地扫描参数，并复用全局 `-o` 控制文件输出。

#### Scenario: 默认自动导出 Excel
- **WHEN** 用户执行 `edr filescan --scan-mode smart` 且未提供 `-o`
- **THEN** 系统在当前目录自动导出 `result*.xlsx` 结果文件

#### Scenario: Excel 输出
- **WHEN** 用户执行 `edr filescan --scan-mode smart -o out.xlsx`
- **THEN** 系统生成 Excel 文件并将结果写入该路径

#### Scenario: Path 模式参数校验
- **WHEN** 用户执行 `edr filescan --scan-mode path` 但未提供 `<path>`
- **THEN** 系统返回中文错误并以非 0 退出

#### Scenario: 旧参数 --scan-path 被拒绝
- **WHEN** 用户执行 `edr filescan --scan-mode path --scan-path /tmp`
- **THEN** 系统返回中文错误并提示改用 `--scan-mode path <path>`

### Requirement: 支持三种扫描模式
系统 SHALL 支持 `full`、`path`、`smart` 三种本地文件扫描模式，并在 `edr filescan -h` 中给出每种模式说明。

#### Scenario: 全盘扫描
- **WHEN** 用户执行 `edr filescan --scan-mode full`
- **THEN** 系统扫描主机所有可用磁盘文件

#### Scenario: 指定路径扫描
- **WHEN** 用户执行 `edr filescan --scan-mode path /tmp`
- **THEN** 系统仅扫描 `/tmp` 目录下的文件

#### Scenario: 智能扫描
- **WHEN** 用户执行 `edr filescan --scan-mode smart`
- **THEN** 系统按智能扫描管线处理目标列表

### Requirement: 输出字段与结果格式
系统 SHALL 以 JSON/CSV/Excel 输出统一结构，包含扫描元信息与扩展采集字段：

- 顶层扫描元信息：`scan_mode`, `source`, `hostname`, `displayIp`, `externalIpList`, `internalIpList`。
- `basic_info`：`file_path`, `file_name`, `file_size_bytes`, `creation_time`, `modification_time`, `access_time`（RFC3339，毫秒精度），以及平台差异字段（Windows: `attributes`；Linux: `owner`, `group`, `mode`）。
- `hashes`：`sha256`, `imphash`。
- `signature`（Windows 可用）：`is_signed`, `signature_valid`, `signer_subject`, `certificate_thumbprint`。
- `binary_info`（仅 PE/ELF 可执行文件）：`magic_bytes`, `imported_libraries`, `sections_info`, `version_info`。
- `context`（Windows 可用）：`motw_zone_id`, `download_url`。

Excel 输出 SHALL 采用扁平化列名 `group.field`（如 `basic_info.file_path`、`hashes.sha256`、`signature.is_signed`），数组/对象字段（如 `imported_libraries`, `sections_info`, `version_info`）在 Excel 中以 JSON 字符串形式输出。

#### Scenario: 字段缺失处理
- **WHEN** 某字段不可获取或不适用（例如非 PE/ELF 文件）
- **THEN** 对应字段在 JSON 中输出为 `null`；`externalIpList/internalIpList` 在无数据时输出空数组

#### Scenario: Excel 数组/对象字段序列化
- **WHEN** `binary_info.imported_libraries` 或 `binary_info.sections_info` 为数组/对象
- **THEN** Excel 单元格中输出其 JSON 字符串序列化结果
