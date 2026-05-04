# Security Baseline (benchmark)

`benchmark` 是 `c-eyes` 的安全基线检查模块，使用原生采集器与 YAML 规则元数据执行基线检查并输出统一结果。

## 能力范围

- 新增统一命令：`c-eyes benchmark`
- 模块定位：仅做基线检查（collection-only），不支持风险分析
- 内置模板：`windows`、`linux`、`euleros`、`kylin`
- 基线等级：`--baseline-level 1|2|3|4`（默认 `1`）
- 模板模式：`--template auto|windows|linux|euleros|kylin`（默认 `auto`）

## 权限要求

- Windows：必须管理员权限运行
- Linux/EulerOS/银河麒麟：必须 root 权限运行
- 权限不足时，命令会直接报错并退出

## 输出说明

- 脚本原始结果：保留 `*_chk.xml` 原始证据文件路径（`raw_xml_path`）
- 结构化结果：输出统一基线结果（含 `summary` 与 `rows`）
- 统一输出方式：复用全局 `-o/--output`（支持 `.json/.csv/.xlsx`）
- 未指定 `-o` 时：默认自动生成 `result*.xlsx`

## 命令示例

默认自动识别模板运行：

```bash
c-eyes benchmark
```

显式指定模板运行：

```bash
c-eyes benchmark --template euleros

c-eyes benchmark --template windows --baseline-level 2
```

显式指定输出文件：

```bash
c-eyes benchmark --template windows -o benchmark.json
```

查看帮助：

```bash
c-eyes benchmark -h
```

## 帮助信息规范

- 提示信息采用英文
- 风格与 `hostscan`、`filescan` 等统一命令保持一致
