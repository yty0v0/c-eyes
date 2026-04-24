# EDR Process Scan Usage

## Build

```bash
go build -o c-eyes ./cmd/edr
```

## Command

```bash
./c-eyes process scan [flags]
```

## Flags

- `-hostname` 主机名（模糊匹配）
- `-ip` 主机 IP（模糊匹配）
- `-startTime` 进程启动时间（RFC3339 或 YYYY-MM-DD）
- `-versions` 版本列表（Windows，仅逗号分隔）
- `-root` 是否 root 权限运行（Linux）
- `-packageName` 包名（Linux）
- `-packageVersions` 包版本列表（Linux，仅逗号分隔）
- `-installedByPm` 是否包管理器安装（Linux）
- `-pids` 进程 ID 列表（逗号分隔）
- `-state` 进程状态（Linux）
- `-path` 进程路径（模糊匹配）
- `-uname` 用户名（模糊匹配，Linux）
- `-gname` 用户组名（模糊匹配，Linux）
- `-name` 进程名（模糊匹配）
- `-startArgs` 启动参数（模糊匹配）
- `-tty` 启动 TTY（模糊匹配，Linux）
- `-description` 进程描述（模糊匹配，Windows）
- `-types` 进程类型列表（Windows，仅逗号分隔）
- `-excel` 输出 Excel 文件（.xlsx），示例：`-excel process-scan.xlsx`

## Optional Host Config

如果需要填充 `bizGroup`、`hostTagList` 等字段，可以提供 JSON 配置文件：

- 运行目录下的 `c-eyes-config.json`，或
- `C_EYES_CONFIG` 环境变量指定路径，或
- `~/.c-eyes/config.json`

示例：

```json
{
  "displayIp": "10.0.0.10",
  "externalIpList": [],
  "internalIpList": ["10.0.0.10"],
  "bizGroupId": 1001,
  "bizGroup": "blue-team",
  "remark": "prod node",
  "hostTagList": ["prod", "linux"]
}
```

## Example Output

```json
[
  {
    "displayIp": "10.0.0.10",
    "externalIpList": [],
    "internalIpList": ["10.0.0.10"],
    "bizGroupId": 1001,
    "bizGroup": "blue-team",
    "remark": "prod node",
    "hostTagList": ["prod", "linux"],
    "hostname": "node-1",
    "startTime": "2026-02-26T06:30:45Z",
    "version": null,
    "root": true,
    "prtCount": null,
    "Md5": "e99a18c428cb38d5f260853678922e03",
    "packageName": "openssh-server",
    "packageVersion": "1:9.6p1-3",
    "installByPm": true,
    "pid": 1234,
    "ppid": 1,
    "path": "/usr/sbin/sshd",
    "startArgs": "/usr/sbin/sshd -D",
    "state": "S",
    "uname": "root",
    "uid": 0,
    "gname": "root",
    "gid": 0,
    "tty": null,
    "name": "sshd",
    "sessionId": null,
    "sessionName": null,
    "type": null,
    "description": null,
    "groups": null,
    "size": null
  }
]
```

## Excel Output

```bash
./c-eyes process scan -name ssh -excel process-scan.xlsx
```

# EDR File Scan Usage

## Command

```bash
./c-eyes file scan -mode [full|path] [-path PATH] [-smart] [-excel out.xlsx]
```

## Flags

- `-mode` 扫描模式：`full`、`path`
- `-path` 指定路径（仅 `mode=path` 需要）
- `-smart` 启用智能子集扫描（仅可与 `mode=full|path` 组合）
- `-excel` 输出 Excel 文件（.xlsx），示例：`-excel file-scan.xlsx`
- `-maxTargets` 扫描目标上限（0 表示不限制）

## Examples

```bash
./c-eyes file scan -mode full -smart
./c-eyes file scan -mode path -path /tmp
./c-eyes file scan -mode path -path /tmp -smart -excel file-scan.xlsx
```

## Output

文件扫描 JSON 输出采用分组结构与 snake_case 字段命名：

- 顶层扫描元信息：`scan_mode`, `smart_enabled`, `source`, `hostname`
- `basic_info`：`file_path`, `file_name`, `file_size_bytes`, `creation_time`, `modification_time`, `access_time`, `attributes`, `owner`, `group`, `mode`
- `hashes`：`sha256`, `imphash`
- `signature`：`is_signed`, `signature_valid`, `signer_subject`, `certificate_thumbprint`
- `binary_info`：`magic_bytes`, `imported_libraries`, `sections_info`, `version_info`
- `context`：`motw_zone_id`, `download_url`

Excel 输出使用扁平化列名 `group.field`（如 `basic_info.file_path`），数组/对象字段（`imported_libraries`, `sections_info`, `version_info`）序列化为 JSON 字符串。

### Example Output

```json
[
  {
    "scan_mode": "path",
    "smart_enabled": true,
    "source": "path",
    "hostname": "node-1",
    "basic_info": {
      "file_path": "/tmp/sample.bin",
      "file_name": "sample.bin",
      "file_size_bytes": 2048,
      "creation_time": null,
      "modification_time": "2026-03-05T09:58:12Z",
      "access_time": "2026-03-05T10:00:00Z",
      "attributes": null,
      "owner": "root",
      "group": "root",
      "mode": "0755"
    },
    "hashes": {
      "sha256": "4fd0101ea...",
      "imphash": null
    },
    "signature": null,
    "binary_info": null,
    "context": null
  }
]
```

# EDR Risk Analysis Usage

## Command

```bash
./c-eyes risk analyze -input scan.json -mode [local_only|cloud_only|fast|smart|deep] [flags]
```

## Flags

- `-input` 扫描结果文件（JSON 数组、NDJSON 或 Excel `.xlsx`）
- `-file` 直接分析单个文件路径（风险分析模块内置路径扫描）
- `-dir` 直接分析目录路径（默认递归分析目录下所有文件）
- `-pid` 按进程 PID 分析（会提取进程可执行路径并进入风险分析）
- `-pname` 按进程名分析（模糊匹配，可命中多个进程）
- `-process-memory` 仅用于 `-pid/-pname`，额外采集并分析进程内存（高级模式，默认关闭）
- `-memory-max-bytes` 每个进程最多采集的内存字节数（默认 `16777216`）
- `-mode` 分析模式：`local_only`、`cloud_only`、`fast`、`smart`、`deep`（唯一模式入口）
- `-yara-rules` YARA-X 规则文件或目录路径（本地模式必填）
- `-yara-read-chunk` 本地文件分析时的分块读取大小（字节，默认 `4194304`）
- `-local-weight` 本地匹配权重（默认 0.6）
- `-cloud-weight` 云端查询权重（默认 0.4）
- `-cloud-upload` 启用云端文件上传最终防线（默认 `false`）
- `-cloud-upload-concurrency` 上传并发（默认 `2`）
- `-cloud-upload-wait` 上传任务等待时长（默认 `0`，按模式自动：`fast=10s`、`smart=3m`、`cloud_only=4m`、`deep=6m`）
- `-cloud-upload-submit-timeout` 上传提交超时（默认 `20s`）
- `-cloud-upload-poll-interval` 上传轮询间隔（默认 `5s`）
- `-cloud-upload-max-size` 上传文件大小上限（默认 `20971520`，即 20MB）
- `-analysis-max-duration` 分析总时长硬上限（默认 `0`，按 `N/U/C` 智能预算）
- `-excel` 输出 Excel 文件（.xlsx）
- `-json` 输出 JSON 文件（默认 stdout）

说明：`process scan`、`file scan`、`risk analyze` 默认都会在 `stderr` 显示实时进度条，不影响 `stdout/json` 输出。

白名单策略（智能/深度分析前置）：
- `C_EYES_WHITELIST_POLICY`：白名单策略文件路径（JSON）
- 自动查找顺序：
1. `C_EYES_WHITELIST_POLICY`
2. 可执行文件同目录 `c-eyes-whitelist.json`
3. 当前目录 `./c-eyes-whitelist.json`
4. `~/.c-eyes/whitelist.json`

白名单漏斗顺序（低成本到高成本）：
1. 本地信誉缓存（safe/malicious）
2. 权威哈希库（NSRL、企业基线）
3. 签名与可信发布者
4. 拒绝规则（证书黑名单、BYOVD）
5. LOLBin 命令行白名单
6. 未命中则进入 YARA-X 与云端分析

运维与应急参考：
- `docs/whitelist-operations.md`
- `docs/whitelist-incident-response.md`

输入源参数互斥：
- 只能选择一类输入源：`-input`、`-file`、`-dir`、`-pid`、`-pname`
- `-process-memory` 只能与 `-pid` 或 `-pname` 搭配

规则路径查找顺序：
1. `-yara-rules`
2. `C_EYES_YARA_RULES`
3. 可执行文件同目录下的 `rules/yaraRules` 或 `rules`

### Cloud Config（推荐）

联网平台参数（`api_key`、`base_url`、`proxy_url`、`rate_limit`、`timeout`、`cache_ttl`）统一通过配置文件维护：

查找顺序：
1. `C_EYES_CLOUD_CONFIG`
2. 可执行文件同目录下的 `c-eyes-cloud.json`
3. 当前目录 `c-eyes-cloud.json`
4. `~/.c-eyes/cloud.json`

示例（`c-eyes-cloud.json`）：

```json
{
  "provider": "virustotal",
  "proxy_url": "http://127.0.0.1:7890",
  "providers": {
    "virustotal": {
      "api_key": "YOUR_VT_API_KEY",
      "base_url": "https://www.virustotal.com",
      "rate_limit": "2s",
      "timeout": "10s",
      "cache_ttl": "10m"
    },
    "hybrid_analysis": {
      "api_key": "YOUR_HA_API_KEY"
    },
    "malwarebazaar": {
      "api_key": "YOUR_MB_API_KEY"
    },
    "otx": {
      "api_key": "YOUR_OTX_API_KEY"
    },
    "triage": {
      "api_key": "YOUR_TRIAGE_API_KEY",
      "base_url": "https://tria.ge/api/v0",
      "proxy_url": "http://127.0.0.1:7891"
    }
  }
}
```

`proxy_url` 为可选项：
- 顶层 `proxy_url`：作为所有平台的默认代理。
- `providers.<name>.proxy_url`：覆盖该平台的代理配置（优先级高于顶层）。

已接入平台：`virustotal`、`hybrid_analysis`、`malwarebazaar`、`otx`、`triage`。
说明：`provider` 字段已忽略，保留仅为兼容旧配置。
联网模式固定为多平台并行查询并聚合评分，不再支持单一平台模式。
项目根目录默认提供 `c-eyes-cloud.json` 模板，打包时不需要把它拷进 `dist-windows-amd64`。  
分发给用户时，把 `c-eyes-cloud.json` 放在可执行文件同目录即可被自动读取。

环境变量回退（优先级低于配置文件）：
- `virustotal`：`VT_API_KEY`
- `hybrid_analysis`：`HA_API_KEY` 或 `HYBRID_ANALYSIS_API_KEY`
- `malwarebazaar`：`MB_API_KEY` 或 `MALWAREBAZAAR_API_KEY`
- `otx`：`OTX_API_KEY`
- `triage`：`TRIAGE_API_KEY`

注意：
- 非引擎类平台返回的是归一化分值（`malicious_votes/total_engines` 以 100 为分母），不代表真实引擎数量。
- `cloud_analysis.cloud_provider` 固定为 `multi`，实际命中的平台列表在 `cloud_analysis.cloud_providers`。
- 云端聚合主分改为“有效平台最高分”（`MAX`），不再使用简单平均。
- `cloud_analysis.effective_average_score` 仅用于观测，分母只统计“成功且有有效结论”的平台。
- 命中恶意威胁标签（如 `webshell`/`trojan`）会触发一票否决，最终风险等级上提为“高危”。
- 命中检出阈值（`malicious>=3` 或检出率 `>5%`）会触发风险兜底，避免落入“无风险”。
- 当 5 平台查询里有 3 个及以上处于 `pending/failed/timeout`，触发故障安全：最终不输出“无风险”，改为“分析中”或“可疑-需本地核实”。
- 当本地模式遇到不可访问的 `target_path`（例如来源于其他主机的路径）时，会对该条记录回退并继续处理：
  - `local_analysis.local_fallback=true`
  - `local_analysis.local_fallback_reason` 包含失败原因
  - `smart/deep` 模式会根据本地标签决定是否继续云端查询
- 进程高级模式（`-process-memory`）会在常规 `process` 记录外，额外生成 `target_type=process_memory` 的记录并做本地 YARA 匹配：
  - 内存采集失败时该条记录回退，失败信息写入 `local_fallback_reason`
  - 该模式依赖系统权限，建议使用管理员权限运行
- 为避免“路径同名误扫本机文件”，本地模式增加了安全校验：
  - 若输入含 `hostname` 且与当前主机不一致，则跳过本地匹配并回退
  - 若输入含 `hashes.sha256/md5/sha1`，会先校验本机同路径文件哈希；不一致则回退，不执行 YARA
  - 若输入同时缺少 `hostname` 和文件哈希，也会回退（避免在身份不明时误扫本机同路径文件）
- 模式策略：
  - `local_only`：YARA-X 不可用时直接报错退出（避免误以为已完成本地检测）
  - `smart`：先本地 YARA-X 预扫描；高确信命中或有效签名白名单会直接跳过联网分析
  - `deep`：在 `smart` 基础上进入深度云端分析（默认 15 分钟超时窗口）
  - 兼容模式：`hybrid` 已废弃，会自动映射为 `smart`

### 云上传最终防线（V2）

上传不是常规路径，而是“最后防线”：

- 默认关闭：只有显式 `-cloud-upload=true` 才允许上传
- 触发前提（全部满足）：
  - 目标可上传（有路径、可读、非目录、大小不超过 `-cloud-upload-max-size`）
  - 前置流程未形成高置信结论
- 高置信结论（任一命中即阻断上传）：
  - 白名单 `allow/deny`
  - 本地高置信命中（例如高危 YARA 严重度）
  - 云哈希高置信命中（例如 provider 分高）
  - 模式已形成明确终判（极低或极高）
- 多平台策略：
  - 上传：`virustotal`、`triage`、`hybrid_analysis`
  - 默认仅哈希查询：`malwarebazaar`、`otx`

### 动态预算（N/U/C）

- `N`：总记录数
- `U`：进入上传阶段的记录数
- `C`：上传并发（`-cloud-upload-concurrency`）

当 `-analysis-max-duration=0` 时，系统按模式基线预算 + 上传预算自动计算总时长；若用户显式设置 `-analysis-max-duration>0`，该值作为全流程硬上限。

### 上传观测字段

风险分析输出（JSON 与 Excel）新增：

- `cloud_upload_enabled`
- `cloud_upload_attempted`
- `cloud_upload_status`（`completed|pending|skipped|failed`）
- `cloud_upload_reason`
- `cloud_upload_providers`
- `cloud_upload_tasks`（`provider/task_id/status/score/link/error`）
- `cloud_upload_duration_ms`

## Build With YARA-X

本地匹配模式需要集成 `yara-x` 的 C API（`yara_x_capi`）。官方推荐使用 `cargo-c` 构建并安装库与头文件：

```bash
cargo install cargo-c
cargo cinstall -p yara-x-capi --release
```

以上步骤会把 `yara_x_capi` 的库与头文件安装到系统路径，并生成 `pkg-config` 配置文件（Linux/macOS 常见路径为 `/usr/local/lib` 与 `/usr/local/include`）。Windows 用户可以在 `target/x86_64-pc-windows-msvc/release` 下找到 `yara_x.h`、`yara_x_capi.dll`/`.lib` 等文件，并将包含/链接路径配置到 `CGO_CFLAGS` 与 `CGO_LDFLAGS`。

示例（Windows）：  
`set CGO_CFLAGS=-IC:\path\to\yara-x\target\x86_64-pc-windows-msvc\release`  
`set CGO_LDFLAGS=-LC:\path\to\yara-x\target\x86_64-pc-windows-msvc\release -lyara_x_capi`

构建时启用 `yarax` 标签并链接本地库：

```bash
go build -tags yarax -o c-eyes ./cmd/edr
```

规则路径可以通过 `-yara-rules` 或 `C_EYES_YARA_RULES` 指定。

### Windows Project-Embedded Build

如果你使用项目内的 `third_party/yara-x-dist`（本仓库默认路径），可以直接运行：

```powershell
.\scripts\build-windows.ps1
```

如果机器上没有 `gcc`，先把便携 MinGW 工具链安装到项目目录（`third_party/toolchain/mingw64`）：

```powershell
.\scripts\setup-windows-toolchain.ps1
.\scripts\build-windows.ps1
```

也可以一条命令自动引导安装并构建：

```powershell
.\scripts\build-windows.ps1 -BootstrapToolchain
```

如果网络不稳定，也可以先手动下载 WinLibs 的 x86_64 zip，再离线安装到项目：

```powershell
.\scripts\setup-windows-toolchain.ps1 -ArchivePath .\downloads\winlibs-x86_64-*.zip
.\scripts\build-windows.ps1
```

脚本会构建 `dist-windows-amd64\c-eyes.exe` 并把 `yara_x_capi.dll` 一起复制到 `dist-windows-amd64` 目录，便于分发。
如果使用项目内工具链，脚本还会自动拷贝 MinGW 运行时 DLL（如 `libgcc_s_seh-1.dll`），确保目标机器无需额外安装编译环境即可运行。

### Linux Project-Embedded Build (开箱即用)

前置依赖：
- Rust + cargo
- cargo-c（`cargo install cargo-c`）
- gcc + pkg-config

如果缺少源码目录，先克隆 YARA-X：

```bash
git clone https://github.com/VirusTotal/yara-x third_party/yara-x-src
```

构建并打包到 `dist-linux-amd64`：

```bash
./scripts/build-linux.sh
```

输出内容：
- `dist-linux-amd64/c-eyes`
- `dist-linux-amd64/libyara_x_capi.so*`
- `dist-linux-amd64/rules/yaraRules`

运行示例（无需额外 `-yara-rules` 参数）：

```bash
./dist-linux-amd64/c-eyes risk analyze -input scan.json -mode local_only
```

## Examples

```bash
# 本地匹配
./c-eyes risk analyze -input scan.json -mode local_only -yara-rules ./rules

# 直接分析单个文件
./c-eyes risk analyze -file C:\Windows\System32\notepad.exe -mode local_only

# 递归分析目录（智能分析）
./c-eyes risk analyze -dir D:\samples -mode smart

# 按 PID 分析进程（深度分析）
./c-eyes risk analyze -pid 1234 -mode deep

# 按进程名分析
./c-eyes risk analyze -pname chrome -mode cloud_only

# 联网查询（云端参数从 c-eyes-cloud.json 读取）
./c-eyes risk analyze -input scan.json -mode cloud_only

# 从扫描导出的 Excel 输入
./c-eyes risk analyze -input scan.xlsx -mode cloud_only

# 智能模式 + Excel 输出（云端参数从 c-eyes-cloud.json 读取）
./c-eyes risk analyze -input scan.json -mode smart -yara-rules ./rules -excel risk.xlsx

# 指定白名单策略文件
$env:C_EYES_WHITELIST_POLICY="D:\policy\c-eyes-whitelist.json"
./c-eyes risk analyze -input scan.json -mode smart
```
