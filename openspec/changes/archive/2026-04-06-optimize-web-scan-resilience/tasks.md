## 1. Config Parsing Resilience

- [x] 1.1 为 web-application 增加 include 递归解析与防循环处理
- [x] 1.2 为 web-site 增加 include 递归解析与防循环处理
- [x] 1.3 在路径归一化中增加软链接真实路径解析

## 2. Runtime State Enrichment

- [x] 2.1 为 web-application 输出新增 `isRunning`
- [x] 2.2 为 web-site 输出新增 `isRunning`
- [x] 2.3 动态关联命中时设置运行状态并保持默认值回退

## 3. Export and Contract Alignment

- [x] 3.1 更新 web-application Excel 导出头与数据行
- [x] 3.2 更新 web-site Excel 导出头与数据行
- [x] 3.3 更新 websitescan golden 基准数据

## 4. Verification

- [x] 4.1 新增 include 解析单元测试
- [x] 4.2 新增复杂参数/相对路径/去重边界测试
- [x] 4.3 运行回归测试并更新 dist 产物

## 5. Deep Testing Record

- [x] 5.1 运行 `go test ./internal/webapplicationscan -count=1 -v`
- [x] 5.2 运行 `go test ./internal/websitescan -count=1 -v`
- [x] 5.3 运行 `go test ./cmd/edr -run "Web(Site|Application)" -count=1 -v`
- [x] 5.4 尝试 `-race`，因本机缺少 gcc/cgo 编译链未执行（已记录环境限制）
