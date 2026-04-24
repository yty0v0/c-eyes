你是一个高级工具开发工程师和网络安全研究员，帮我撰写一下edr工具的jar包信息获取部分，要保证windows和linux都可以使用，不要通过命令行来获取这些信息，这块只进行信息收集不进行风险分析，使用go语言来写，支持输出excel和json两种格式，通过命令行来使用该工具，编码使用utf-8，提示信息用中文。
基本要求：

(1)请求参数
参数	类型	必填	说明
groups	Integer数组	否	业务组ID
hostname	String	否	主机名（模糊查询）
ip	String	否	主机IP（模糊查询）
name	String	否	包名
version	String数组	否	版本
type	Integer数组	否	类型（1：应用程序，2：系统类库，3:web服务自带库，8：其他依赖包）
executable	布尔数组	否	是否可执行
path	String	否	绝对路径

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
name	String	varchar(512)	包名
version	String	varchar(512)	版本
type	String	varchar(128)	类型
executable	布尔	tinyint(2)	是否可执行
path	String	varchar(128)	绝对路径

(3)对于内外网ip的收集采用数组形式，收集全部的内外网ip，参考其它模块在此处的设计，单一存储的参数可以去掉

(4)信息收集的方法可以参考web应用扫描和web站点扫描的模块，采用静态+动态的方式。