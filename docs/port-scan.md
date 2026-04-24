你是一个高级工具开发工程师和网络安全研究员，帮我撰写一下edr工具的端口信息获取部分，要保证windows和linux都可以使用，不要通过命令行来获取这些信息，这块只进行信息收集不进行风险分析，使用go语言来写，支持输出excel和json两种格式，通过命令行来使用该工具。
要求：
(1)要包含tcp全连接扫描和tcp-syn半开扫描两种扫描方式，默认使用tcp全连接扫描
(2)请求参数如下：
参数	类型	必填	说明
groups	Integer数组	否	业务组ID
hostname	String	否	主机名（模糊查询）
ip	String	否	主机IP（模糊查询）
proto	String数组	否	协议
port	Integer	否	端口
bindIp	String	否	绑定ip
processName	String	否	进程名（模糊查询）
(3)返回参数如下：
字段	类型	长度	说明
displayIp	String	varchar(15)	显示IP
externalIpList	String数组	varchar(15)	外网IP列表
internalIpList	String数组	varchar(15)	内网IP列表
bizGroupId	Integer	bigint(20)	业务组ID
bizGroup	String	varchar(128)	业务组名
remark	String	varchar(1024)	备注
hostTagList	String数组	varchar(1024)	标签
proto	String	varchar(512)	协议
port	Integer	int(10)	端口号
pid	Integer	int(10)	进程id
processName	String	varchar(128)	进程名
bindIp	String	varchar(15)	绑定ip
status	Integer	tinyint(4)	端口状态：-1 - 端口状态未知；0 – 仅内网可访问；1 - 外网可访问,null不存在该字段
(4)对于内外网ip的收集和其它扫描模式的收集对其。
