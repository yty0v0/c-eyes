# 环境变量扫描（environment-scan）

## 能力说明

- 采集范围：Windows 与 Linux 环境变量信息
- 采集约束：仅使用进程内 API / 系统数据源，不通过外部命令行采集
- 输出格式：支持 JSON 与 Excel
- 能力边界：仅信息收集，不做风险分析

## CLI 用法

```bash
c-eyes environment-scan [参数] [-output json|excel] [-excel out.xlsx]
```

示例：

```bash
c-eyes environment-scan \
  --hostname node \
  --ip 192.168 \
  --key PATH \
  --value bin \
  --user root \
  --sysEnv true,false \
  --output excel \
  --excel ./environment-scan.xlsx
```

## 请求参数

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| groups | Integer 数组 | 否 | 业务组 ID |
| hostname | String | 否 | 主机名（模糊查询） |
| ip | String | 否 | 主机 IP（模糊查询） |
| key | String | 否 | 环境变量名（模糊查询） |
| value | String | 否 | 环境变量值（模糊查询） |
| user | String | 否 | 用户（模糊查询） |
| sysEnv | Boolean 数组 | 否 | 环境变量类型（`true` 系统变量，`false` 用户变量） |

## 返回字段

| 字段 | 类型 | 说明 |
|---|---|---|
| displayIp | String | 主机展示 IP |
| externalIpList | String 数组 | 外网 IP 列表 |
| internalIpList | String 数组 | 内网 IP 列表 |
| bizGroupId | Integer | 业务组 ID |
| bizGroup | String | 业务组名 |
| remark | String | 备注 |
| hostTagList | String 数组 | 标签 |
| hostname | String | 主机名 |
| key | String | 环境变量名 |
| value | String | 环境变量值 |
| user | String | 用户 |
| sysEnv | Boolean | 环境变量类型 |

说明：内外网 IP 统一采用数组字段输出，覆盖主机全量地址。
