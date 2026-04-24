## Why

当前文件扫描结果字段过于精简，难以满足后端威胁情报碰撞、签名可信度校验与二进制启发式分析的需求，导致检测准确性与可解释性受限。基于 `filescan-desgin1.md` 的新增采集要求，需要尽快统一输出参数与数据模型。

## What Changes

- 扩展文件扫描输出结构，覆盖基础元数据、密码学指纹、数字签名、二进制内部特征与上下文信息。
- 增加平台差异化字段（Windows 文件属性、Linux Owner/Group/Mode），并在不可获取时输出 `null`/空值。
- 更新 JSON/Excel 输出字段集合与命名，保证与新数据模型一致。

## Capabilities

### New Capabilities
- (none)

### Modified Capabilities
- `file-scan`: 调整文件扫描输出字段与采集范围，新增哈希/签名/二进制特征/上下文信息要求。

## Impact

- 影响文件扫描数据采集逻辑与结果序列化（JSON/Excel）。
- 需要新增/调整哈希计算、签名解析、PE/ELF 解析与 MOTW 读取能力。
- 相关测试与下游解析（若有）需同步更新字段映射。
