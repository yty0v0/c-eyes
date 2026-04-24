你是一个高级工具开发工程师和网络安全研究员，帮我撰写一下edr工具的用户组信息获取部分，要保证windows和linux都可以使用，不要通过命令行来获取这些信息，这块只进行信息收集不进行风险分析，使用go语言来写，支持输出excel和json两种格式，通过命令行来使用该工具

请求参数：
字段	类型	长度	说明
groups	Integer数组	否	业务组ID
hostname	String	否	主机名（模糊查询）
ip	String	否	主机IP（模糊查询）
name	String	否	用户组名（模糊查询）
gid	long	否	用户组id（仅支持linux）

返回参数：
字段	类型	长度	说明
displayIp	String	varchar(15)	显示IP
externalIpList	String数组	varchar(15)	外网IP列表
internalIpList	String数组	varchar(15)	内网IP列表
bizGroupId	Integer	bigint(20)	业务组ID
bizGroup	String	varchar(128)	业务组名
remark	String	varchar(1024)	备注
hostTagList	String	varchar(1024)	标签
hostname	String	varchar(512)	主机名
name	String	varchar(128)	用户组名
gid	Integer	bigint(20)	用户组id（仅支持linux）
members	Object	name ：varchar(128) type：tinyint(4)	组成员，仅windows name: 用户名 type: 用户类型
description	String	varchar(1024)	用户组描述，仅windows
