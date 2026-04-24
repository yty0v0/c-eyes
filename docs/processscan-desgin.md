你是一个高级工具开发工程师和网络安全研究员，帮我撰写一下edr工具，要求使用go语言，
通过命令行的命令来使用该工具，命令执行完直接出扫描结果。
现在先来设计进程信息扫描，要求如下：
1.不使用让主机从命令行执行命令的方式探测，要使用其它方式，可以根据系统的内部函数来探测
2.执行进程信息扫描时输入的参数包括:
参数	        类型	        必填	    说明
hostname	    String	        否	    主机名（模糊查询）
ip	            String	        否	    主机IP（模糊查询）
startTime	    Date	        否	    进程启动时间
versions	    String数组	    否	    版本，仅windows可用
root	        Boolean	        否	    是否root权限运行，仅linux可用
packageName	    String	        否	    包名,仅linux可用
packageVersions	String数组	    否	    包版本列表,仅linux可用
installedByPm	Boolean	        否	    是否包安装进程 ,仅linux可用
pids	        Integer数组	    否	     进程id
state	        String	        否	    进程状态,仅linux可用
path	        String	        否	    进程路径（模糊查询）
uname	        String	        否	    用户名（Linux模糊查询）
gname	        String	        否	    用户组名（模糊查询）,仅linux可用
name	        String	        否	    进程名（模糊查询）
startArgs	    String	        否	    进程启动参数（模糊查询）
tty	            String	        否	    进程启动的TTY（模糊查询），仅linux可用
description	    String	        否	    进程描述（模糊查询），仅windows可用
types	        Integer数组	    否	    进程类型查询(其中：1-表示应用程序 2-表示后台程序 3-表示windows进程)），仅windows可用

3.返回的结果参数内容如下：
字段	        类型	        长度	     说明
displayIp	    String	    varchar(15)	    显示IP
externalIpList	String数组	varchar(15)	    外网IP列表
internalIpList	String数组	varchar(15)	    内网IP列表
bizGroupId	    Integer	    bigint(20)	    业务组ID
bizGroup	    String	    varchar(128)	业务组名
remark	        String	    varchar(1024)	备注
hostTagList	    String数组	varchar(1024)	标签
hostname	    String	    varchar(512)	主机名
startTime	    Date	    date	        进程启动时间
version	        String	    varchar(512)	进程版本，仅windows可用
root	        Boolean	    tinyint(1)	    是否root权限启动，仅linux可用
prtCount	    Integer	    tinyint(4)	    进程端口数
Md5	            String	    varchar(32)	    可执行文件md5
packageName	    String	    varchar(512)	进程对应软件包名称，仅linux可用
packageVersion	String	    varchar(512)	进程对应软件包版本，仅linux可用
installByPm	    Boolean	    tinyint(1)	    是否包管理器安装，Windows为空
pid	            Integer	    int(10)	        进程ID
ppid	        Integer	    int(10)	        父进程ID
path	        String	    varchar(512)	进程路径
startArgs	    String	    varchar(2048)	进程启动参数
state	        String	    varchar(2)	    进程状态，仅linux可用
uname	        String	    varchar(128)	用户名
uid	            Integer	    bigint(20)	    用户id
gname	        String	    varchar(128)	用户组名
gid	            Integer	    bigint (20)	    用户组id，仅linux可用
tty	            String	    varchar(512)	进程启动的TTY，仅linux可用
name	        String	    varchar(128)	进程名
sessionId	    Integer	    int(10)	        会话id, 仅windows可用
sessionName	    String	    varchar(128)	会话名，仅windows可用
type	        Integer	    tinyint(4)	    进程类型，1-应用程序 2-后台程序 3-windows进程，仅windows可用
description	    String	    varchar(512)	进程描述，仅windows可用
groups	        String数组	varchar(128)	进程用户组，仅windows可用
size	        Integer	    int(10)	        进程可执行文件大小，仅windows可用

4.如果有的结果参数没有扫描出来结果，则显示null
