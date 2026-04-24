## MODIFIED Requirements

### Requirement: 输出字段完整性
系统 SHALL 为每条结果输出以下字段（不可缺失）：
`displayIp`, `externalIpList`, `processExternalIpList`, `internalIpList`, `bizGroupId`, `bizGroup`, `remark`, `hostTagList`, `hostname`, `startTime`, `version`, `root`, `prtCount`, `Md5`, `packageName`, `packageVersion`, `installByPm`, `pid`, `ppid`, `path`, `startArgs`, `state`, `uname`, `uid`, `gname`, `gid`, `tty`, `name`, `sessionId`, `sessionName`, `type`, `description`, `groups`, `size`。

#### Scenario: 字段缺失处理
- **WHEN** 某字段无法获取或平台不支持
- **THEN** 该字段输出为 `null`；`externalIpList/processExternalIpList/internalIpList` 在无数据时输出空数组

## ADDED Requirements

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
