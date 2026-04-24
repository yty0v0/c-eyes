你是一个高级工具开发工程师和网络安全研究员，帮我撰写一下edr工具的系统账号信息获取部分，不要通过命令行来获取这些信息，这块只进行信息收集不进行风险分析，使用go语言来写

基本要求：
请求参数
参数	类型	必填	说明
groups	Integer数组	否	业务组ID
hostname	String	否	主机名（模糊查询）
ip	String	否	主机IP（模糊查询）
status	Integer数组	否	帐号状态 linux 账号状态，1:启用，0:禁用 ；windows 账号状态，0:启用，2:禁用
name	String	否	账号名
home	String	否	home目录（模糊查询）
lastLoginTime	DateRange	否	最后一次登录时间
gid	Integer	否	用户组id
uid	Integer	否	用户id

返回参数
字段	类型	长度	说明
displayIp	String	varchar(15)	显示IP
externalIpList	String数组	varchar(15)	外网IP列表
internalIpList	String数组	varchar(15)	内网IP列表
bizGroupId	Integer	bigint(20)	业务组ID
bizGroup	String	varchar(128)	业务组名
remark	String	varchar(1024)	备注
hostTagList	String数组	varchar(1024)	标签
hostname	String	varchar(512)	主机名
uid	Integer	bigint(20)	账号uid
gid	Integer	bigint(20)	用户组id
groups	String	varchar(128)	账户组
name	String	varchar(128)	账号名称
status	Integer数组	tinyint(4)	账号状态 linux 账号状态，1:启用，0:禁用 ；windows 账号状态，0:启用，1：锁定，2:禁用
home	String	varchar(512)	home目录
shell	String	varchar(512)	用户shell，仅linux可用
loginStatus	Integer	tinyint(4)	登录状态，0不可登入 1不可交互登入 2可交互登入，3 key&pwd登陆 ，仅linux可用
lastLoginTime	Date	date	最后登录时间
pwdMaxDays	Integer	int(10)	密码到期天数， null为不限
pwdMinDays	Integer	int(10)	密码多少天后可修改，nul为不限
pwdWarnDays	Integer	int(10)	密码到期告警天数，null为不限
sshAcl	String	varchar(3)	~./ssh访问权限, 如”777”, “666”，仅linux可用
comment	String	varchar(1024)	帐号备注，仅linux可用
lastLoginTty	String	varchar(1024)	最后登录终端，仅linux可用
lastLoginIp	String	varchar(15)	最后登录ip，仅linux可用
expireTime	Date	date	帐号到期时间，仅linux可用
expired	Boolean	int(10)	是否过期
fullName	String	varchar(128)	用户全名，仅Windows可用
sudoAccesses	List	shell：varchar(128) user：varchar(128)	sudo权限 shell:权限 user:用户权限
root	Boolean	tinyint(1)	是否是root，仅linux可用
description	String	varchar(512)	用户描述，仅Windows可用
type	Integer	tinyint(4)	账号类型仅windows可用 1 user 2 组 4 别名组 5 WellKonwn组 6 已删除用户组 8 未知类型
lastChangPwdTime	Date	date	密码最后修改时间
accountLoginType	Integer	tinyint(4)	账户登录方式，仅linux可用 0 不可登陆 1 key登陆 2 pwd登陆 3 key&pwd登陆
interactiveLoginType	Integer	tinyint(4)	交互登录方式，仅linux可用 0 不可登录 1 不可交互登录 2 可交互登录
passwordInactiveDays	Integer	int(10)	密码过期后变成无效的天数，-1为无限
sudo	Boolean	tinyint(1)	是否sudo权限，仅linux可用
authorizedKeys	Object数组	encryptType：varchar(512) comment：varchar(512) value：varchar(512) MD5：varchar(32)	账号公钥信息，仅linux可用 encryptType：加密类型 comment：备注信息 value：公钥的值 MD5：MD5

json输出结果格式示例：
{
    "total":1,
    "rows":[
        {
            "displayIp":"172.16.2.231",
            "connectionIp":"172.16.2.231",
            "externalIpList":[],
            "internalIpList":["172.16.2.231"],
            "bizGroupId":39,
            "bizGroup":"qingteng",
            "remark":null,
            "hostTagList":[
                "test-test000",
                "tmp"
            ],
            "hostname":"qingteng",
            "uid":116,
            "gid":65534,
            "groups":[
                "nogroup"
            ],
            "name":"kernoops",
            "home":"/",
            "shell":"/bin/false",
　　　　"root": false,
            "status":0,
            "lastLoginTime":"1970-01-01 08:00:00",
            "pwdMaxDays":99999,
            "pwdMinDays":-1,
            "pwdWarnDays":7,
            "loginStatus":0,
            "sshAcl":"",
　　　　"sudoAccesses": [],
            "comment":"Kernel Oops Tracking Daemon,,,",
            "lastLoginTty":"",
            "lastLoginIp":"",
            "expireTime":"1969-12-31 08:00:00",
            "expired":false,
            "fullName":null,
            "description":null,
            "lastChangPwdTime": "2017-09-04 08:00:00",
            "accountLoginType": 3,
            "interactiveLoginType": 2,
            "passwordInactiveDays": null,
            "sudo": true,
            "authorizedKeys": [
                {
                    "encryptType": "ssh-dss",
                    "comment": "root@centos-master",
                    "value": "AAAAB3Nz...+fgkXA==",
                    "md5": "36e4313ab5b1aae15ff0f1948a4d73ea"
                }
            ]
        }
    ]
}

## CLI使用示例

```bash
c-eyes account scan \
  --hostname qingteng \
  --ip 172.16 \
  --status 0,1 \
  --name kern \
  --home / \
  --gid 65534 \
  --uid 116 \
  --lastLoginFrom 2026-01-01 \
  --lastLoginTo 2026-12-31
```

输出结构：

```json
{
  "total": 1,
  "rows": [
    {
      "name": "kernoops",
      "uid": 116,
      "gid": 65534
    }
  ]
}
```
