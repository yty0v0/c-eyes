## ADDED Requirements

### Requirement: 全局输出参数按路径后缀识别格式
系统 SHALL 提供全局 `-o` 输出参数，`-o` 后接输出文件路径，并根据后缀识别输出格式：`.json`、`.csv`、`.xlsx`。

#### Scenario: JSON 文件输出
- **WHEN** 用户执行命令并提供 `-o result.json`
- **THEN** 系统以 JSON 格式写入 `result.json`

#### Scenario: CSV 文件输出
- **WHEN** 用户执行命令并提供 `-o result.csv`
- **THEN** 系统以 CSV 格式写入 `result.csv`

#### Scenario: Excel 文件输出
- **WHEN** 用户执行命令并提供 `-o result.xlsx`
- **THEN** 系统生成 Excel 文件 `result.xlsx`

#### Scenario: 不支持的后缀
- **WHEN** 用户执行命令并提供 `-o result.txt`
- **THEN** 系统返回中文错误并提示仅支持 json/csv/xlsx

#### Scenario: 使用 -o 但未提供路径
- **WHEN** 用户执行命令并提供 `-o`（或 `-o=`）但未提供有效输出路径
- **THEN** 系统返回中文参数错误并提示 `-o/--output` 必须指定输出路径

### Requirement: 未提供 -o 时默认自动导出 Excel 结果文件
系统 MUST 在未提供 `-o` 时自动在当前目录导出 Excel 文件，文件名按 `result.xlsx`、`result1.xlsx`、`resultN.xlsx` 规则递增，避免覆盖已有文件。

#### Scenario: 默认导出首个文件名
- **WHEN** 用户执行 `edr hostscan` 且未提供 `-o`
- **THEN** 系统在当前目录生成 `result.xlsx`

#### Scenario: 按最大序号递增导出
- **WHEN** 当前目录已存在 `result1.xlsx`（以及任意更大序号 `resultN.xlsx`）
- **THEN** 系统默认导出 `result(N+1).xlsx`

### Requirement: 全局输出参数适用于扫描与风险分析结果
系统 SHALL 对扫描结果与风险分析结果统一应用全局 `-o` 输出规则。

#### Scenario: 扫描串联分析结果导出 CSV
- **WHEN** 用户执行 `edr filescan -r -o analysis.csv`
- **THEN** 系统将风险分析结果以 CSV 形式写入 `analysis.csv`

#### Scenario: 独立风险分析导出 Excel
- **WHEN** 用户执行 `edr -r -file hosts.json -o risk.xlsx`
- **THEN** 系统将风险分析结果导出为 Excel 文件 `risk.xlsx`
