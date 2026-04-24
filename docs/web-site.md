你是一个高级工具开发工程师和网络安全研究员，帮我撰写一下edr工具的web站点信息获取部分，要保证windows和linux都可以使用，不要通过命令行来获取这些信息，这块只进行信息收集不进行风险分析，使用go语言来写，支持输出excel和json两种格式，通过命令行来使用该工具，编码使用utf-8，提示信息使用中文提示。
基本要求：

(1)请求参数
参数	类型	必填	说明
groups	Integer数组	否	业务组ID
hostname	String	否	主机名（模糊查询）
ip	String	否	主机IP（模糊查询）
port	Integer	否	站点端口
proto	String	否	站点协议，精确匹配
type	String数组	否	服务类型，精确匹配，如iis,nginx等
rootPath	String	否	站点路径，模糊匹配

(2)返回参数
字段	类型	长度	说明
displayIp	String	varchar(15)	显示IP
externalIp	String	varchar(15)	外网IP
internalIp	String	varchar(15)	内网IP
bizGroupId	Integer	bigint(20)	业务组ID
bizGroup	String	varchar(128)	业务组名
remark	String	varchar(1024)	备注
hostTagList	String数组	varchar(1024)	标签
hostname	String	varchar(512)	主机名
pid	Integer	int(10)	进程id
allow	String	varchar(1024)	允许地址，仅Linux及
deny	String	varchar(1024)	拒绝地址，仅Linux及Windows-nginx
cmd	String	varchar(512)	进程启动命令行参数
domains	List	name: varchar(128) title：varchar(512) ip：varchar(15)	域名信息列表 name：域名名称 title：标题 ip：绑定ip
user	String	varchar(512)	启动服务用户
type	String	varchar(10)	站点类型，如nginx，http
port	Integer	int(10)	端口
proto	String	varchar(10)	协议
portStatus	Integer	tinyint(4)	端口状态:-1 - 端口状态未知; 0 – 仅内网可访问;1 - 外网可访问
securityEnabled	Boolean	tinyint(1)	是否开启安全模块 false- 未开启 true-开启 （仅Linux及Windows-nginx）
virtualDir	List	path：varchar(1024) physicalPath：varchar(1024) root：tinyint(1) owner：varchar(512) group：bigint(20) permission: varchar(7) acls aceType：tinyint(4) user: varchar(512) userType：tinyint(4) accessMask:bigint(20) appPath: varchar(1024) appPool name: varchar(512) identityType: tinyint(4) user: varchar(512)	虚拟目录信息 path：虚拟地址 physicalPath：物理地址 root：是否主目录 owner：目录所有者 group：目录所属用户组 仅linux permission：目录权限 仅linux acls：仅windows aceType ace类型 user 用户名 userType 用户类型 accessMask 访问控制掩码数组 appPath: 应用程序路径 （仅Windows-IIS） appPool: 程序池信息（仅Windows-IIS） name 程序池名称 identityType 运行账户标识 user 运行账户名
root	Object	参考虚拟目录	主目录信息 path：虚拟地址 physicalPath：物理地址 root：是否主目录 owner：目录所有者 group：目录所属用户组 仅linux permission：目录权限 仅linux acls：仅windows aceType ace类型 user 用户名 userType 用户类型 accessMask 访问控制掩码数组 appPath: 应用程序路径 （仅Windows-IIS） appPool: 程序池信息（仅Windows-IIS） name 程序池名称 identityType 运行账户标识 user 运行账户名
virtualDirCount	Integer	int(10)	虚拟路径数
bindingCount	Integer	int(10)	绑定地址数
deployPath	String	varchar(4096)	War包部署总目录（仅Linux-Tomcat/Weblogic/JBoss/Wildfly/Jetty）
configName	String	varchar(4096)	仅IIS可用，站点别名
state	Integer	tinyint(4)	仅IIS可用，站点状态
path	String	varchar(4096)	仅WINDOWS的weblogic\webshpere\jetty\wildfly使用，站点物理地址

(3)对于内外网ip的收集采用数组形式，收集全部的内外网ip，参考其它模块在此处的设计，单一存储的参数可以去掉