## 1. Setup

- [x] 1.1 新建 `internal/accountscan` 模块骨架（`types.go`、`scan.go`、`filter.go`、平台文件）
- [x] 1.2 定义 `AccountScanParams`、`DateRange`、`AccountInfo` 与顶层输出结构 `AccountScanResult`
- [x] 1.3 复用或抽象主机元数据注入能力（`displayIp/externalIp/internalIp/bizGroup*`）

## 2. Core Implementation

- [x] 2.1 实现账号扫描主流程：采集、主机字段注入、过滤、结果规范化
- [x] 2.2 实现过滤规则：`groups/hostname/ip/status/name/home/lastLoginTime/gid/uid`
- [x] 2.3 实现统一字段兜底策略（不可采集字段输出 `null` 或空集合）

## 3. Linux Implementation

- [x] 3.1 实现 `/etc/passwd` 解析并映射账号基础字段
- [x] 3.2 实现 `/etc/group` 与组归属解析，填充 `groups`
- [x] 3.3 实现 `/etc/shadow` 解析，填充密码策略、状态、过期相关字段
- [x] 3.4 实现 `authorized_keys` 解析与 `sshAcl` 权限读取
- [x] 3.5 实现 `/etc/sudoers` 与 `/etc/sudoers.d` 解析，填充 `sudo/sudoAccesses`
- [x] 3.6 实现 Linux 登录记录解析（`lastLoginTime/lastLoginTty/lastLoginIp`），失败时降级为 `null`

## 4. Windows Implementation

- [x] 4.1 基于 Windows 账户管理 API 实现本地账号枚举与基础字段采集
- [x] 4.2 实现 Windows 账号状态、类型、描述、姓名、口令时间等字段映射
- [x] 4.3 实现 Windows 组信息采集并映射到 `groups`
- [x] 4.4 实现 SID 到稳定数值 `uid/gid` 的映射策略

## 5. CLI & Output

- [x] 5.1 在 `cmd/edr/main.go` 增加 `account scan` 子命令与参数解析
- [x] 5.2 实现时间范围参数解析（RFC3339、`YYYY-MM-DD`）并映射到 `lastLoginTime`
- [x] 5.3 输出规范化 JSON：顶层 `total` + `rows`，字段名与文档一致
- [x] 5.4 补充命令帮助文本与示例输出说明

## 6. Tests & Verification

- [x] 6.1 为 Linux 文本解析器添加 fixture 单测（passwd/group/shadow/sudoers/authorized_keys）
- [x] 6.2 为过滤器添加表驱动单测，覆盖模糊匹配、数组匹配与时间范围匹配
- [x] 6.3 为 Windows 采集层添加可注入接口与 mock 单测
- [x] 6.4 添加端到端输出结构测试，验证 `total/rows` 与字段完整性
- [x] 6.5 执行 `go test ./...` 并修复回归问题
