你是一个高级工具开发工程师和网络安全研究员，帮我撰写一下edr工具的启动项信息获取部分，要保证windows和linux都可以使用，不要通过命令行来获取这些信息，这块只进行信息收集不进行风险分析，使用go语言来写，支持输出excel和json两种格式，通过命令行来使用该工具。
基本要求：
(1)请求参数：
参数	类型	必填	说明
groups	Integer数组	否	业务组ID
hostname	String	否	主机名（模糊查询）
ip	String	否	主机IP（模糊查询）
name	String	否	启动项名（模糊查询）（仅linux启动项名）
initLevel	Interger数组	否	默认启动模式 (仅linux)
defaultOpen	布尔数组	否	默认模式启用状态（仅linux）
isXinetd	布尔数组	否	启动方式 （仅linux）
showName	String	否	启动项名（仅windows）
user	String	否	服务启动用户windows
enable	布尔	否	服务的状态windows
startType	Integer数组	否	启动类型windows
publisher	String	否	发布者windows

(2)返回参数：
字段	类型	长度	说明
displayIp	String	varchar(15)	主机IP
externalIpList	String数组	varchar(15)	外网IP列表
internalIpList	String数组	varchar(15)	内网IP列表
bizGroupId	Integer	bigint(20)	业务组ID
bizGroup	String	varchar(128)	业务组名
remark	String	varchar(1024)	备注
hostTagList	String数组	varchar(1024)	标签
hostname	String	varchar(512)	主机名
name	String	varchar(512)	启动项名
defaultOpen	布尔	tinyint(2)	默认模式启用状态
rc0	Integer	bigint(16)	停机(rc0)
rc1	Integer	bigint(16)	单用户模式(rc1)
rc2	Integer	bigint(16)	多用户无NFS模式(rc2)
rc3	Integer	bigint(16)	完全多用户模式(rc3)
rc4	Integer	bigint(16)	预留模式(rc4)
rc5	Integer	bigint(16)	桌面模式(rc5)
rc6	Integer	bigint(16)	重新启动(rc6)
rc7	Integer	bigint(16)	单用户自启动(rcs)
initLevel	Interger	bigint(16)	默认启动模式(仅linux)
xinetd	布尔	tinyint(2)	启动方式
user	String	varchar(128)	服务启动用户windows
enable	布尔	tinyint(2)	服务的状态windows
startType	Integer	bigint(16)	启动类型windows
publisher	String	varchar(64)	发布者windows
showName	String	varchar(128)	启动项名（仅windows）

(3)对于内外网ip的收集和其它扫描模式的收集对其。
