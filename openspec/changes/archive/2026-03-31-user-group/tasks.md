## 1. Setup

- [x] 1.1 新建 `internal/usergroupscan` 模块骨架（`types.go`、`scan.go`、`filter.go`、`scan_linux.go`、`scan_windows.go`）
- [x] 1.2 定义 `UserGroupScanParams`、`UserGroupInfo`、`GroupMember` 与顶层结果结构（`total` + `rows`）
- [x] 1.3 复用或抽象主机元数据注入能力（`displayIp/externalIp/internalIp/bizGroup*`）

## 2. Core Implementation

- [x] 2.1 实现用户组扫描主流程：平台采集、主机字段注入、过滤、结果规范化
- [x] 2.2 实现过滤规则：`groups`、`hostname`、`ip`、`name`、`gid`
- [x] 2.3 实现字段完整性兜底策略（不可采集字段输出 `null` 或空集合）

## 3. Linux Implementation

- [x] 3.1 实现 `/etc/group` 解析并映射 `name/gid/members`
- [x] 3.2 实现 Linux 组成员归一化逻辑（空成员、重复成员、异常行兼容）
- [x] 3.3 为 Linux 平台补充 `description`/Windows 专属字段空值兜底

## 4. Windows Implementation

- [x] 4.1 基于系统本地组 API 实现用户组枚举与基础字段采集
- [x] 4.2 实现 Windows 组描述字段映射（`description`）
- [x] 4.3 实现 Windows 成员映射（`members.name`、`members.type`）并补齐 Linux 专属字段空值兜底

## 5. CLI & Output

- [x] 5.1 在 `cmd/edr/main.go` 增加 `user-group scan` 子命令与参数解析
- [x] 5.2 实现 `-output json|excel` 与 `-excel` 参数校验及输出分支
- [x] 5.3 新增用户组结果 Excel 导出表头与字段映射，保证列顺序稳定
- [x] 5.4 补充命令帮助文本与使用示例

## 6. Tests & Verification

- [x] 6.1 为 Linux 组文件解析与边界场景添加 fixture 单测
- [x] 6.2 为过滤器添加表驱动单测（模糊匹配、数组匹配、gid 精确匹配）
- [x] 6.3 为 Windows 采集层增加可注入接口与 mock 单测
- [x] 6.4 增加端到端输出结构测试，验证 `total/rows` 与字段完整性
- [x] 6.5 执行 `go test ./...` 并修复回归问题
