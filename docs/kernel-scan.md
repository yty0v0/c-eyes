# 内核模块扫描（kernel-scan）
## 能力说明

- 采集范围：Windows 与 Linux 内核模块信息
- 采集约束：仅使用系统 API / 系统文件数据源，不通过外部命令行采集
- 输出格式：支持 JSON 与 Excel
- 能力边界：仅做信息收集，不做风险分析

## CLI 用法

```bash
c-eyes kernel-scan [参数] [-output json|excel] [-excel out.xlsx]
```

示例：

```bash
c-eyes kernel-scan \
  --groups 39,40 \
  --hostname node \
  --ip 192.168 \
  --moduleName tcp \
  --path drivers \
  --version 10.0.26100.1,1.4 \
  --output excel \
  --excel ./kernel-scan.xlsx
```

## 请求参数

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| groups | Integer 数组 | 否 | 业务组 ID |
| hostname | String | 否 | 主机名（模糊查询） |
| ip | String | 否 | 主机 IP（模糊查询） |
| moduleName | String | 否 | 模块名称（模糊查询） |
| path | String | 否 | 模块路径（模糊查询） |
| version | String 数组 | 否 | 模块版本 |

## 返回字段

| 字段 | 类型 | 说明 |
|---|---|---|
| displayIp | String | 主机显示 IP |
| externalIps | String 数组 | 外网 IP 列表 |
| internalIps | String 数组 | 内网 IP 列表 |
| bizGroupId | Integer | 业务组 ID |
| bizGroup | String | 业务组名 |
| remark | String | 备注 |
| hostTagList | String 数组 | 标签 |
| hostname | String | 主机名 |
| moduleName | String | 模块名称 |
| description | String | 模块描述 |
| path | String | 模块路径 |
| version | String | 模块版本 |
| size | String | 模块大小（字节字符串） |
| depends | String 数组 | 其依赖的内核模块 |
| holders | String 数组 | 依赖其的内核模块 |

说明：内外网 IP 统一采用数组字段输出，覆盖主机全部可见地址。
