# Process Info Scan

## Purpose

定义进程信息扫描能力的行为边界、过滤规则与跨平台输出契约，确保 `c-eyes process scan` 以一致结构返回进程资产数据，并明确该能力仅用于信息收集而不包含风险分析。
## Requirements
### Requirement: CLI 支持进程信息扫描
系统 SHALL 提供 `c-eyes process scan` 命令，接收指定参数并将结果直接输出到标准输出（JSON 数组）。

#### Scenario: 默认扫描
- **WHEN** 用户执行 `c-eyes process scan` 且未提供过滤参数
- **THEN** 系统返回 JSON 数组（可为空），并以成功状态退出

### Requirement: 进程枚举不依赖外部命令
系统 MUST 使用系统内部接口获取进程信息（Windows API 或 Linux `/proc`），不得通过命令行调用外部工具。

#### Scenario: 扫描执行路径
- **WHEN** 执行进程扫描
- **THEN** 系统仅调用操作系统内部接口获取数据，不启动外部命令进程

### Requirement: 输入参数与匹配规则
系统 SHALL 接收以下输入参数用于过滤：
`hostname`, `ip`, `startTime`, `versions`, `root`, `packageName`, `packageVersions`, `installedByPm`, `pids`, `state`, `path`, `uname`, `gname`, `name`, `startArgs`, `tty`, `description`, `types`。

其中“模糊查询”字段（hostname/ip/path/uname/gname/name/startArgs/tty/description）采用大小写不敏感的子串匹配；`pids`/`types`/`versions`/`packageVersions` 为数组匹配“包含任一即匹配”；`startTime` 过滤为“进程启动时间 >= 指定时间”。

#### Scenario: 模糊匹配
- **WHEN** 用户提供 `--name=ssh`
- **THEN** 返回进程名包含“ssh”的进程（大小写不敏感）

#### Scenario: PID 列表匹配
- **WHEN** 用户提供 `--pids=123,456`
- **THEN** 仅返回 pid 为 123 或 456 的进程

### Requirement: 输出字段完整性
系统 SHALL 为每条结果输出以下字段（不可缺失）：
`displayIp`, `externalIpList`, `processExternalIpList`, `internalIpList`, `bizGroupId`, `bizGroup`, `remark`, `hostTagList`, `hostname`, `startTime`, `version`, `root`, `prtCount`, `Md5`, `packageName`, `packageVersion`, `installByPm`, `pid`, `ppid`, `path`, `startArgs`, `state`, `uname`, `uid`, `gname`, `gid`, `tty`, `name`, `sessionId`, `sessionName`, `type`, `description`, `groups`, `size`。

#### Scenario: 字段缺失处理
- **WHEN** 某字段无法获取或平台不支持
- **THEN** 该字段输出为 `null`；`externalIpList/processExternalIpList/internalIpList` 在无数据时输出空数组

### Requirement: 进程扫描输出主机内外网 IP 列表
系统 SHALL 在每条进程扫描记录中输出 `internalIpList` 与 `externalIpList`，分别表示主机所有内网与外网 IPv4 地址集合。

#### Scenario: 多网卡主机输出
- **WHEN** 主机存在多个内网 IPv4 地址
- **THEN** `internalIpList` 返回全部内网地址

#### Scenario: 无外网地址输出
- **WHEN** 主机未识别到外网 IPv4 地址
- **THEN** `externalIpList` 返回空数组

### Requirement: 平台特有字段处理
系统 SHALL 仅在对应平台填充平台特有字段：
- Windows：`version`, `description`, `sessionId`, `sessionName`, `type`, `groups`, `size`
- Linux：`root`, `packageName`, `packageVersion`, `installByPm`, `state`, `gid`, `tty`, `gname`

#### Scenario: 非平台字段
- **WHEN** 在 Linux 执行扫描
- **THEN** Windows 专有字段输出为 `null`

### Requirement: Linux 包信息解析
系统 SHALL 在 Linux 上尝试通过本地包管理数据库（如 dpkg/rpm 数据库）解析 `packageName/packageVersion/installByPm`，且 MUST 不调用外部命令；无法解析时返回 `null`。

#### Scenario: 包信息不可用
- **WHEN** 无法从本地包管理数据库解析包信息
- **THEN** `packageName/packageVersion/installByPm` 输出为 `null`

### Requirement: 进程扫描输出进程维度外联公网 IP 列表
系统 SHALL 在每条进程扫描记录中输出 `processExternalIpList`，表示该进程关联的外联公网 IPv4 地址集合；`externalIpList` SHALL 继续表示主机维度外网 IPv4 地址集合，两者语义 MUST 区分。

#### Scenario: 进程存在外联公网连接
- **WHEN** 某进程被识别到一个或多个外联公网 IPv4 连接
- **THEN** `processExternalIpList` 返回该进程对应的公网 IPv4 地址列表（去重后）

#### Scenario: 进程无外联公网连接
- **WHEN** 某进程未识别到外联公网 IPv4 连接
- **THEN** `processExternalIpList` 返回空数组

#### Scenario: 主机外网与进程外联语义分离
- **WHEN** 主机存在外网 IPv4 地址但某进程无外联公网连接
- **THEN** `externalIpList` 可非空且 `processExternalIpList` 仍返回空数组

