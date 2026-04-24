你是一个高级工具开发工程师和网络安全研究员，帮我撰写一下edr工具的软件应用信息获取部分，要保证windows和linux都可以使用，不要通过命令行来获取这些信息，这块只进行信息收集不进行风险分析，使用go语言来写通过命令行来使用该工具，编码使用utf-8。
基本要求：

(1)请求参数
参数	类型	必填	说明
groups	Integer数组	否	业务组ID
hostname	String	否	主机名（模糊查询）
ip	String	否	主机IP（模糊查询）
name	String	否	软件应用名称（模糊查询）
version	String数组	否	软件应用版本
binPath	String	否	linux为二进制路径，windows 为安装路径（模糊查询）
configPath	String	否	配置文件路径（模糊查询）

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
name	String	varchar(512)	软件应用名
version	String	varchar(512)	版本号
uname	String	varchar(128)	启动用户
binPath	String	varchar(1024)	windows为安装路径，Linux为二进制路径
configPath	String	varchar(1024)	配置文件路径
processes	List	pid：int(10) name：varchar(512) uname:varchar(512)	关联进程列表 pid:进程id name:进程名 uname:进程启动用户

(3)对于内外网ip的收集采用数组形式，收集全部的内外网ip，参考其它模块在此处的设计，单一存储的参数可以去掉

(4)信息收集的方法可以参考web应用扫描和web站点扫描的模块，采用静态+动态的方式。

(5)把这个作为一个模块放到filescan大模块里，和site,framework,jarpackage这三个模块对齐，需要补充提示信息的地方你按照现在提示信息的格式补充上，还是采用英文，要保证完美的嵌入进现有的代码。