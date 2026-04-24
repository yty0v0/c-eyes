## 1. 数据模型与接口定义

- [x] 1.1 定义 `kernel-scan` 结果数据结构，包含主机字段、模块字段、`externalIps[]` 与 `internalIps[]`
- [x] 1.2 定义 `KernelScanProvider` 抽象接口与统一调用入口
- [x] 1.3 在 CLI 层新增 `kernel-scan` 命令与参数绑定（groups/hostname/ip/moduleName/path/version）

## 2. 平台采集实现

- [x] 2.1 实现 Linux 平台内核模块采集（基于系统接口或文件系统来源，禁止 shell 命令）
- [x] 2.2 实现 Windows 平台内核模块采集（基于原生 API，禁止 shell 命令）
- [x] 2.3 统一模块字段映射（名称、描述、路径、版本、大小、depends、holders）与空值兜底策略

## 3. 过滤与导出链路

- [x] 3.1 实现 `groups`、`hostname`、`ip`、`moduleName`、`path`、`version` 过滤逻辑并接入扫描流程
- [x] 3.2 接入 JSON 导出，确保数组字段按规范序列化
- [x] 3.3 接入 Excel 导出，定义数组字段的稳定列映射与序列化格式

## 4. 测试与验收

- [x] 4.1 为过滤逻辑编写单元测试（含模糊匹配与数组过滤场景）
- [x] 4.2 为 Windows/Linux 采集层编写平台测试或可替代的 mock 测试
- [x] 4.3 增加 JSON/Excel 导出结果校验测试，验证字段完整性与格式一致性
- [x] 4.4 更新使用文档与示例命令，覆盖两种导出格式和典型筛选条件
