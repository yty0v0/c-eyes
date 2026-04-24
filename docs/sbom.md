# SBOM 模块接入说明

## 目标
将本地 `C:\Users\Administrator\Desktop\sbom` 代码并入 `edrsystem`，作为统一 CLI 下的独立模块 `sbom`，与 `hostscan/filescan/eventlog/netscan` 对齐。

## 功能定位
- `sbom` 仅做信息采集与 SBOM 文档生成。
- `sbom` 不做风险分析，不支持 `-r/--riskanalyze` 及风险分析专用参数。
- 实现需支持 Windows 和 Linux。
- 提示与报错信息使用英文。

## 命令约定
- 子命令：`c-eyes sbom`
- 格式参数：`--format <name>`
- 支持值：`xspdx-json`、`spdx-json`
- 默认值：`xspdx-json`

## 输出约定
输出设置：
- `-o, --output <path>`      输出路径（根据指定后缀识别，支持： `.json/.csv/.xlsx`），默认(不启用 `-o`)时在当前目录下输出 `result*.xlsx` 文件

SBOM 模块补充规则（在全局输出规则基础上）：
- `sbom` 不新增 `-p/--path` 参数，沿用全局 `-o/--output`。
- `sbom` 显式传入 `-o` 时，仅允许 `.json` 后缀；传入 `.csv/.xlsx` 需报错。
- `sbom` 未传入 `-o` 时，默认输出为当前目录自动命名的 `result*.json`：
  - `result.json`
  - `result1.json`
  - `resultN.json`（按已存在最大序号递增）

## 备注
- 文档编码统一为 UTF-8。
