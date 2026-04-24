## 1. Web Application Dynamic Association

- [x] 1.1 为 `webapplicationscan` 增加进程关联增强入口
- [x] 1.2 实现服务类型识别与配置路径提取（从进程路径/参数）
- [x] 1.3 复用静态解析器补全动态发现配置的应用元数据

## 2. Web Site Dynamic Association

- [x] 2.1 为 `websitescan` 增加进程关联增强入口
- [x] 2.2 实现 `pid`、`cmd`、`user` 运行态字段补全
- [x] 2.3 支持从动态配置路径解析并合并站点记录

## 3. Quality and Regression

- [x] 3.1 增加 web-application 动态关联单测
- [x] 3.2 增加 web-site 动态关联单测
- [x] 3.3 回归运行 `internal/webapplicationscan`、`internal/websitescan`、`cmd/edr` 相关测试

## 4. Distribution Update

- [x] 4.1 更新 `dist-windows-amd64/edr.exe`
- [x] 4.2 更新 `dist-linux-amd64/edr`
