你是一个高级工具开发工程师和网络安全研究员，帮我撰写一下edr工具的内网主机探测部分，要保证windows和linux都可以使用，不要通过命令行来获取这些信息，这块只进行信息收集不进行风险分析，使用go语言来写，输出使用全局命令-o实现，通过命令行来使用该工具，编码使用utf-8，提示和报错信息用英文。

(1)请求执行参数
参数	类型	长度	说明
target	String	varchar(1024)	本次扫描目标，支持 CIDR、IP范围、IP列表（可混合逗号分隔，支持 IPv6）。未填写时默认扫描本机在线私网网段。(如 192.168.1.0/24、fe80::/64、192.168.1.10,192.168.1.20）)
targetFile	String	varchar(255)	目标文件路径（UTF-8；每行一个 IP/CIDR；空行和 # 注释忽略；与 target 合并去重）
scanMode	String	varchar(64)	扫描模式，可单选或多选（逗号分隔）：A(ARP)、ICP(ICMP-PING)、ICA(ICMP-ADDRESSMASK)、ICT(ICMP-TIMESTAMP)、T(TCP-CONNECT)、TS(TCP-SYN)、U(UDP)、N(NETBIOS)、O(OXID)。
ipv6	Boolean	tinyint(1)	是否启用 IPv6 探测（模式支持哪些 IPv6 就执行哪些）
exclude	String	varchar(1024)	排除目标（CIDR/IP，逗号分隔，支持 IPv6），优先级高于 target/targetFile
tcpPorts	String	varchar(128)	TCP 端口列表（逗号分隔；用于 T/TS，如 22,80,135,139,443,445,3389）
udpPorts	String	varchar(128)	UDP 端口列表（逗号分隔；用于 U，如 53,137,161）
maxTargets	Integer	int(11)	本次任务最大目标数（安全阈值；超限拒绝执行）
pps	Integer	int(11)	全局发包速率上限（每秒包数；动态调节默认始终启用，pps 为手动上限）
timeoutMs	Integer	int(11)	单目标探测超时（毫秒）
jitterMs	Integer	int(11)	发包抖动（毫秒；每次随机延迟 0~jitterMs）
workers	Integer	int(11)	并发 worker 数（动态调节默认始终启用，workers 为手动上限）
managedSource	String	varchar(255)	通过指定已纳管资产源文件路径（json/csv/xlsx），用于扫描后判定扫描结果是否在已纳管资产里managed/unmanaged，不参与发包。匹配规则：优先 ip+mac，其次 ip；MAC 比对前做归一化（大小写和分隔符统一）。

(2)请求过滤参数
参数	类型	长度	说明
assetStatus	String	varchar(32)	状态过滤：managed/unmanaged/ignored
keyword	String	varchar(255)	全局搜索（IP/MAC/主机名）
sortBy	String	varchar(32)	排序字段：lastSeen/firstSeen/ipAddress/assetStatus
sortOrder	String	varchar(8)	排序方向：asc/desc

(3)返回参数
参数	类型	长度	说明
total	Long	bigint(20)	满足过滤条件的资产总数
rows	Array<Object>	List	资产条目列表
rows[].assetId	String	varchar(64)	资产唯一 ID（稳定 ID）
rows[].ipAddress	String	varchar(45)	资产 IP（IPv4/IPv6）
rows[].ipVersion	String	varchar(8)	ipv4/ipv6
rows[].macAddress	String	varchar(17)	MAC 地址（IPv6/部分模式下可为空）
rows[].macVendor	String	varchar(128)	MAC OUI 厂商
rows[].hostname	String	varchar(255)	主机名
rows[].osFamily	String	varchar(64)	OS 推断（如 windows/linux/unknown）
rows[].deviceType	String	varchar(64)	设备类型推断（如 pc/server/iot/network_device）
rows[].assetStatus	String	varchar(32)	managed/unmanaged/ignored
rows[].alive	Boolean	tinyint(1)	是否存活（至少一个模式命中）
rows[].firstSeen	Long	bigint(20)	首次发现时间（ms, UTC）
rows[].lastSeen	Long	bigint(20)	最近发现时间（ms, UTC）
rows[].confidence	Integer	int(11)	识别置信度（0~100）
rows[].scanModes	Array<String>	List	命中该资产的模式集合（如 A,ICP,T,U）
rows[].sources	Array<String>	List	发现来源（如 arp/icmp/tcp_syn/udp/netbios/oxid）
rows[].openPorts	Array<Integer>	List	开放端口总集合（去重）
rows[].openTcpPorts	Array<Integer>	List	开放 TCP 端口
rows[].openUdpPorts	Array<Integer>	List	开放 UDP 端口
rows[].portScanModes	Array<String>	List	参与端口探测的模式（T/TS/U）
rows[].ignoredReason	String	varchar(255)	ignored 原因
(4)该功能单独做成netscan模块，和hostscan,filescan,eventlog这些模块对齐

(5)观察cpu和内存占用情况，动态调整并发，扫描速率等问题，可以参考已有代码的实现

(6)这个功能不支持-r风险分析，只进行信息收集

(7)在提示信息里把请求执行参数和请求过滤参数分开写，分成EXECUTE OPTIONS 和 FILTER OPTIONS两个部分，方便用户查看。
