## 1. Setup

- [x] 1.1 初始化 Go module 与 CLI 骨架（`edr process scan` 命令）
- [x] 1.2 定义输入参数与输出结果的数据模型（含指针/可空字段）
- [x] 1.3 设计主机信息获取与可选配置加载（用于 bizGroup/hostTag 等字段）

## 2. Core Implementation

- [x] 2.1 实现跨平台进程扫描接口与调度层（按 OS 路由）
- [x] 2.2 实现过滤器：模糊匹配、数组匹配、`startTime` 过滤规则
- [x] 2.3 实现结果规范化与 JSON 输出（缺失字段输出 null）

## 3. Linux Implementation

- [x] 3.1 实现 `/proc` 解析获取 pid/ppid/uid/gid/startTime/cmdline/path 等
- [x] 3.2 实现 Linux 特有字段：root/state/tty/username/groupname
- [x] 3.3 实现包信息解析（dpkg/rpm 数据库），不调用外部命令

## 4. Windows Implementation

- [x] 4.1 使用 Windows API 枚举进程并获取基础字段
- [x] 4.2 解析可执行文件版本/描述/MD5/size
- [x] 4.3 获取 session 与类型/用户组等 Windows 特有字段

## 5. Tests & Docs

- [x] 5.1 编写过滤逻辑与字段规范化的单元测试
- [x] 5.2 添加平台分支测试（Linux `/proc` mock，Windows API stub）
- [x] 5.3 补充 CLI 使用文档与示例输出
## 6. Excel Output

- [x] 6.1 添加 Excel 输出参数（--excel）
- [x] 6.2 实现 Excel 写入逻辑（.xlsx）
- [x] 6.3 更新使用文档（Excel 输出）
