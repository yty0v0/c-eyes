你是一个高级工具开发工程师和网络安全研究员，帮我撰写一下edr工具的web应用信息获取部分，要保证windows和linux都可以使用，不要通过命令行来获取这些信息，这块只进行信息收集不进行风险分析，使用go语言来写，支持输出excel和json两种格式，通过命令行来使用该工具，编码使用utf-8。
基本要求：

(1)请求参数
参数	类型	必填	说明
groups	Integer数组	否	业务组ID
hostname	String	否	主机名（模糊查询）
ip	String	否	主机IP（模糊查询）
version	String数组	否	应用版本
appName	String	否	应用名
rootPath	String	否	根路径
webRoot	String	否	站点根路径
serverName	String数组	否	服务类型，如nginx、apache、tomcat
domainName	String	否	域名

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
version	String	varchar(512)	应用版本
webRoot	String	varchar(1024)	站点根路径
serverName	String	varchar(128)	站点类型
domainName	String	varchar(512)	域名
pluginCount	Integer	int(10)	插件数
appName	String	varchar(512)	应用名
description	String	varchar(512)	描述
rootPath	String	varchar(512)	根路径
plugins	Object	pluginName：varchar(512) pluginUri：varchar(1024) description：varchar(1024) author：varchar(512) authorUri：varchar(1024) version：varchar(512)	插件信息列表 pluginName：插件名 pluginUri：插件官网链接 description：插件描述 author：作者 authorUri：作者地址 version：版本

(3)对于内外网ip的收集采用数组形式，收集全部的内外网ip，参考其它模块在此处的设计，单一存储的参数可以去掉