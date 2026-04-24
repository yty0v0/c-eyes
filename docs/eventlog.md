你是一个高级工具开发工程师和网络安全研究员，帮我撰写一下edr工具的日志信息获取模块(是获取主机的日志信息不是edr的)，不要通过命令行来获取这些信息，使用go语言来写，这块只进行信息收集不进行风险分析，通过命令行来使用该工具，编码使用utf-8。

基本要求：
(1)请求参数：
字段	类型	长度/取值	必填	说明
startTime	Long	bigint(20)	是	查询开始时间（毫秒时间戳，UTC）
endTime	Long	bigint(20)	是	查询结束时间（毫秒时间戳，UTC）
pageNo	Integer	int(11)，默认 1	否	当前页码
pageSize	Integer	int(11)，默认 20，最大 200	否	每页条数
sources	Array<String>	每项 varchar(32)	否	日志源（如 system/security/application/syslog/auth/audit/kern）
eventTypes	Array<String>	每项 varchar(32)	否	事件类型（如 process/file/network/registry/account/service/login/system）
eventLevels	Array<String>	debug/info/notice/warn/error/critical/fatal	否	事件等级（非威胁等级）
eventCodes	Array<String>	每项 varchar(64)	否	事件编号（跨平台统一用字符串）
eventActions	Array<String>	每项 varchar(32)	否	动作（如 create/modify/delete/start/stop/connect/login/logout）
result	Array<String>	success/fail/unknown	否	事件结果
processName	String	varchar(255)	否	进程名/进程路径（模糊）
processId	Integer	int(11)	否	进程 PID（精确）
username	String	varchar(128)	否	用户名（模糊）
targetPath	String	varchar(512)	否	目标路径（文件/注册表/URL，模糊）
localIp	String	varchar(45)	否	本地 IP
localPort	Integer	int(11)	否	本地端口
remoteIp	String	varchar(45)	否	远端 IP
remotePort	Integer	int(11)	否	远端端口
protocols	Array<String>	每项 varchar(16)	否	协议（tcp/udp/http/https/...）
keyword	String	varchar(255)	否	全文关键字（模糊）
sortBy	String	timestamp/eventLevel/source/eventType/processName，默认 timestamp	否	排序字段
sortOrder	String	asc/desc，默认 desc	否	排序方向
includeRawContent	Boolean	默认 false	否	是否返回原始日志扩展内容

(2)返回参数：
字段路径	类型	长度/取值	说明
total	Long	bigint(20)	满足条件的总记录数
pageNo	Integer	int(11)	当前页码
pageSize	Integer	int(11)	每页条数
hasMore	Boolean	tinyint(1)	是否还有下一页
rows	Array<Object>	-	日志记录列表
rows[].logId	String	varchar(64)	日志唯一 ID
rows[].timestamp	Long	bigint(20)	日志时间（毫秒时间戳，UTC）
rows[].osType	String	varchar(16)	系统类型（windows/linux）
rows[].source	String	varchar(32)	日志源
rows[].eventType	String	varchar(32)	事件类型
rows[].eventLevel	String	varchar(16)	事件等级
rows[].eventCode	String	varchar(64)	事件编号
rows[].eventAction	String	varchar(32)	事件动作
rows[].result	String	varchar(16)	事件结果（success/fail/unknown）
rows[].hostname	String	varchar(255)	主机名
rows[].displayIp	String	varchar(45)	展示 IP
rows[].internalIpList	Array<String>	varchar(45) 数组	内网 IP 列表
rows[].externalIpList	Array<String>	varchar(45) 数组	外网 IP 列表
rows[].username	String	varchar(128)	用户名
rows[].processName	String	varchar(255)	进程名/路径
rows[].processId	Integer	int(11)	进程 PID
rows[].parentProcessName	String	varchar(255)	父进程名
rows[].parentProcessId	Integer	int(11)	父进程 PID
rows[].targetPath	String	varchar(512)	目标路径
rows[].localIp	String	varchar(45)	本地 IP
rows[].localPort	Integer	int(11)	本地端口
rows[].remoteIp	String	varchar(45)	远端 IP
rows[].remotePort	Integer	int(11)	远端端口
rows[].protocol	String	varchar(16)	协议
rows[].message	String	varchar(2048)	事件摘要信息
rows[].rawContent	Object/String	JSON/Text	原始扩展内容（仅 includeRawContent=true 返回）

(3)这个模块是一个单独的大模块，和hostscan，filescan这两个模块对齐，加上这个以后就是hostscan，filescan，eventlog三个大模块了。

(4)这个模块不支持风险分析，就算单独的日志信息收集模块，不支持-r这些风险分析参数，可以增加报错的提示。

(5)该模块的提示信息参考hostscan，filescan的提示信息格式写，才用全英文，启动命令直接用c-eyes eventlog就行，-h查看提示信息。