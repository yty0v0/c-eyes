# Kernel Scan

## Purpose

定义内核模块信息采集能力的行为边界、过滤规则与跨平台输出契约，确保 `c-eyes kernel-scan` 在 Linux 与 Windows 上以一致结构返回内核模块资产数据，并明确该能力仅用于信息收集而不包含风险分析。

## Requirements

### Requirement: Cross-platform kernel module collection
The system SHALL collect kernel module information on both Windows and Linux without invoking shell commands, and SHALL normalize the results into a unified record structure.

#### Scenario: Collect kernel modules on Windows host
- **WHEN** the user runs `kernel-scan` against a Windows host
- **THEN** the system collects module records using Windows-native APIs and returns normalized fields including module identity, path, version, size, dependency links, and host context

#### Scenario: Collect kernel modules on Linux host
- **WHEN** the user runs `kernel-scan` against a Linux host
- **THEN** the system collects module records using Linux-native sources (non-shell) and returns the same normalized field set as Windows

### Requirement: Query filters for kernel module scan
The system SHALL support optional filters `groups`, `hostname`, `ip`, `moduleName`, `path`, and `version` for kernel module query and export.

#### Scenario: Filter by business group and hostname
- **WHEN** the user provides `groups` and `hostname`
- **THEN** only records whose business group is in `groups` and whose hostname matches the fuzzy pattern are returned

#### Scenario: Filter by module attributes
- **WHEN** the user provides `moduleName`, `path`, or `version`
- **THEN** only module records matching the provided conditions are included in output

### Requirement: Multi-IP host representation
The system SHALL represent host network addresses as arrays and SHALL include all discovered external and internal IPs for each host.

#### Scenario: Host with multiple NICs
- **WHEN** a host has multiple internal or external addresses
- **THEN** the output includes all discovered addresses in `internalIps` and `externalIps` arrays without truncation

### Requirement: JSON and Excel export
The system SHALL export kernel scan results in JSON and Excel formats through the CLI workflow.

#### Scenario: Export as JSON
- **WHEN** the user selects JSON output
- **THEN** the system writes normalized kernel scan records to a JSON file with complete fields

#### Scenario: Export as Excel
- **WHEN** the user selects Excel output
- **THEN** the system writes normalized kernel scan records to an Excel file with stable column mapping for scalar and array fields
