## 1. Data Model and Module Skeleton

- [x] 1.1 定义 `DatabaseRecord` 统一结构，覆盖通用字段与平台特有扩展字段
- [x] 1.2 定义请求过滤结构（groups、hostname、ip、name、versions、port、confPath、logPath、dataDir）
- [x] 1.3 建立 `database-scan` 模块目录与采集器接口（collector abstraction）

## 2. Cross-platform Collectors

- [x] 2.1 实现 Linux 采集器（不通过外部命令），从系统接口与配置/运行信息中提取数据库元数据
- [x] 2.2 实现 Windows 采集器（不通过外部命令），从系统接口与配置/运行信息中提取数据库元数据
- [x] 2.3 实现平台特有字段填充逻辑（MySQL/MongoDB/HBase/Oracle/SQL Server）

## 3. Filtering and Normalization

- [x] 3.1 实现文本类字段模糊匹配过滤（hostname、ip、confPath、logPath、dataDir）
- [x] 3.2 实现数组与数值过滤（groups、versions、port）
- [x] 3.3 实现内外网 IP 数组归一化，确保多地址完整保留

## 4. Output and CLI

- [x] 4.1 实现 JSON 序列化输出（默认格式）
- [x] 4.2 接入 Excel 导出能力并建立稳定列映射
- [x] 4.3 新增 CLI 子命令与参数解析，支持输出路径与输出格式选择

## 5. Validation and Guardrails

- [x] 5.1 增加单元测试：过滤逻辑、字段映射、IP 数组表示
- [x] 5.2 增加集成测试：Windows/Linux 样例数据下的输出一致性
- [x] 5.3 增加约束校验：扫描结果仅包含信息收集内容，不产生风险分析字段
