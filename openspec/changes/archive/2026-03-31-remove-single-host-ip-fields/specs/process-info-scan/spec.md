## MODIFIED Requirements

### Requirement: 输出字段完整性
系统 SHALL 为每条结果输出以下字段（不可缺失）：
`displayIp`, `externalIpList`, `internalIpList`, `bizGroupId`, `bizGroup`, `remark`, `hostTagList`, `hostname`, `startTime`, `version`, `root`, `prtCount`, `Md5`, `packageName`, `packageVersion`, `installByPm`, `pid`, `ppid`, `path`, `startArgs`, `state`, `uname`, `uid`, `gname`, `gid`, `tty`, `name`, `sessionId`, `sessionName`, `type`, `description`, `groups`, `size`。

#### Scenario: 字段缺失处理
- **WHEN** 某字段无法获取或平台不支持
- **THEN** 该字段输出为 `null`；`externalIpList/internalIpList` 在无数据时输出空数组
