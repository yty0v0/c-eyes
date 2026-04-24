你是一个高级工具开发工程师和网络安全研究员，帮我撰写一下edr工具的计划任务信息获取部分，要保证windows和linux都可以使用，不要通过命令行来获取这些信息，这块只进行信息收集不进行风险分析，使用go语言来写，支持输出excel和json两种格式，通过命令行来使用该工具。
基本要求：
(1)请求参数：
参数	类型	必填	说明
groups	Integer数组	否	业务组ID
hostname	String	否	主机名（模糊查询）
ip	String	否	主机IP（模糊查询）
user	String数组	否	执行用户
execPath	String	否	执行命令或脚本
conf	String	否	配置文件
taskTime	DateRange	否	执行时间
taskType	String	否	任务类型（仅CRONTAB/AT/BATCH三类）

(2)返回参数：
字段	类型	长度	说明
displayIp	String	varchar(15)	主机IP
externalIp	String	varchar(15)	外网IP
internalIp	String	varchar(15)	内网IP
bizGroupId	Integer	bigint(20)	业务组ID
bizGroup	String	varchar(128)	业务组名
remark	String	varchar(1024)	备注
hostTagList	String数组	varchar(1024)	标签
hostname	String	varchar(512)	主机名
user	String	varchar(512)	执行用户
execTime	String	varchar(64)	执行周期
execPath	String	varchar(512)	执行命令或脚本
conf	String	varchar(512)	配置文件
taskTime	DateRange	bigint(10)	执行时间
taskId	Integer	bigint(20)	任务Id
taskType	String	varchar(15)	任务类型
crondOpen	布尔	tinyint(2)	启用状态

(3)对于内外网ip的收集采用数组形式，收集全部的内外网ip，参考其它模块在此处的设计，单一存储的参数可以去掉