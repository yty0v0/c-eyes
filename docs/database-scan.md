你是一个高级工具开发工程师和网络安全研究员，帮我撰写一下edr工具的数据库信息获取部分，要保证windows和linux都可以使用，不要通过命令行来获取这些信息，这块只进行信息收集不进行风险分析，使用go语言来写，支持输出excel和json两种格式，通过命令行来使用该工具。
基本要求：

(1)请求参数
参数	类型	必填	说明
groups	Integer数组	否	业务组ID
hostname	String	否	主机名（模糊查询）
ip	String	否	主机IP（模糊查询）
name	String	否	数据库类型
versions	String数组	否	数据库版本
port	Integer	否	监听端口
confPath	String	否	配置文件路径（模糊查询）
logPath	String	否	日志文件路径（模糊查询）
dataDir	String	否	数据路径（模糊查询）

(2)返回参数
字段	类型	长度	说明
displayIp	String	varchar(15)	主机IP
externalIp	String	varchar(15)	外网IP
internalIp	String	varchar(15)	内网IP
bizGroupId	Integer	bigint(20)	业务组ID
bizGroup	String	varchar(128)	业务组名
remark	String	varchar(1024)	备注
hostTagList	String数组	varchar(1024)	标签
hostname	String	varchar(512)	主机名
name	String	varchar(512)	数据库类型
version	String	varchar(512)	数据库版本
port	Integer	int(10)	监听端口
protoType	String	varchar(128)	协议
user	String	varchar(128)	运行用户
bindIp	String	varchar(1024)	绑定IP
confPath	String	varchar(1024)	配置文件路径
logPath	String	varchar(1024)	日志文件路径
dataDir	String	varchar(1024)	数据路径
pluginDir	String	varchar(1024)	插件目录,仅Linux MySQL
rest	String	varchar(5)	是否开放rest:'true';'false',仅Linux MongoDB
auth	String	varchar(8)	是否开启安全认证:'enabled'; 'disabled',仅Linux MongoDB
web	String	varchar(5)	是否开启web接口:'true'; 'false',仅Linux MongoDB
webPort	Integer	int(10)	web界面端口,仅Linux HBase
webAddress	String	varchar(1024)	web界面地址,仅Oracle以及Linux HBase
regionServer	List	varchar(128)	region server列表,仅Linux HBase
dbName	String	varchar(128)	数据库示例名,仅windows
loginModel	Integer	tinyint(4)	身份验证,仅windows SQL Server
auditLevel	Integer	tinyint(4)	审核级别,仅windows SQL Server
sysLogPath	String	varchar(1024)	系统日志路径,仅windows SQL Server
mainDbPath	String	varchar(1024)	主数据库路径,仅windows SQL Server

(3)对于内外网ip的收集采用数组形式，收集全部的内外网ip，参考其它模块在此处的设计，单一存储的参数可以去掉