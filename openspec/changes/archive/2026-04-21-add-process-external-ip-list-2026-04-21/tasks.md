## 1. 输出契约与数据模型

- [ ] 1.1 在进程扫描结果结构体中保留 `externalIpList`（主机维度）并新增 `processExternalIpList`（进程维度），确保 JSON tag 与字段名一致。
- [ ] 1.2 统一 `processExternalIpList` 空值行为：无数据时输出 `[]`，不输出 `null`。
- [ ] 1.3 确认扫描聚合逻辑不会把 `processExternalIpList` 回写或覆盖到 `externalIpList`。

## 2. 输出链路一致性

- [ ] 2.1 校验 `c-eyes process scan` 标准输出中包含 `processExternalIpList` 字段且类型为数组。
- [ ] 2.2 同步导出链路（如 Excel 列定义与映射）包含 `processExternalIpList`，列名与 JSON 字段一致。
- [ ] 2.3 针对无外联进程样本验证 `processExternalIpList=[]`，并确认 `externalIpList` 仍按主机维度输出。

## 3. 测试与验证

- [ ] 3.1 增加/更新单元测试，覆盖新增字段序列化、空数组默认值与字段语义分离。
- [ ] 3.2 执行深度扫描回归（包含多进程样本）并核验 `processExternalIpList` 与实际连接观测一致。
- [ ] 3.3 回归现有消费场景，确认仅新增字段不会破坏原有解析逻辑。

## 4. OpenSpec 与交付收尾

- [ ] 4.1 运行 `openspec validate --strict --change add-process-external-ip-list-2026-04-21` 并修复校验问题。
- [ ] 4.2 生成/更新发布产物（`dist`）并确认字段变更已进入交付包。
