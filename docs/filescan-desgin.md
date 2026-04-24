你是一个工具开发和网络安全工程师，现在要继续添加edr系统的功能，当前要添加的功能是文件扫描，要求如下
(1)包括三种扫描模式，全盘扫描，指定文件路径扫描，智能扫描，全盘扫描是指扫描主机上的所有磁盘文件。指定文件路径扫描是指指定文件路径进行扫描，只扫描该路径下的文件。

(2)下面是智能扫描模块设计的详细说明：
EDR 智能扫描 (Smart Scan) 模块系统设计文档
目标： 在极低系统资源消耗（CPU/Memory/IO）下，精准覆盖 90% 以上的高危入侵路径和近期活跃威胁。
核心逻辑： 采用“漏斗过滤模型”（定向收集 -> 快速白名单/缓存过滤 -> 深度扫描）。

1. 核心管线流转 (Pipeline Pipeline)
扫描任务需按以下顺序经过四个核心微模块：

Target Collector (目标收集器): 不遍历文件树，按需提取高危路径。

Filter Engine (过滤引擎): 剔除安全文件，减少扫描引擎压力。

Deep Scanner (深度扫描引擎): 执行实际的恶意代码检测。

Result Reporter (结果上报器): 处置威胁并更新缓存。

2. 各模块核心功能与实现规范
2.1 Target Collector (目标收集器)
指引： 负责生成待扫描的 List<FilePath>。

活跃进程模块： 遍历系统当前运行的进程可执行文件（.exe）及已加载的模块（.dll / .so）。

持久化项 (Persistence)： 读取注册表启动项（Run/RunOnce）、系统服务目录、计划任务目录、启动文件夹。

高危落脚点： 用户级目录（%USERPROFILE%\Downloads, %TEMP%, AppData）、回收站。

近期变动文件： (关键) 调用 Windows USN Journal (更新序列号日志) 或 Linux inotify，直接拉取过去 24 小时内新建或被修改过的 PE 文件（.exe, .dll, .sys）和脚本文件。

2.2 Filter Engine (过滤引擎)
指引： 负责对收集到的文件列表进行免杀/放行判定，必须按以下顺序短路执行：

本地缓存比对 (Local Cache Hit)：

查询本地 SQLite 库。如果记录存在，且文件的 LastModifiedTime (MTime) 和 FilePath 与数据库一致，直接复用历史安全结果，跳过后续所有步骤。

信任签名校验 (Trust Signature)：

解析文件数字签名（Authenticode）。若是受信任的发布者（如 Microsoft, 官方内核签发），直接标记安全并写入缓存。

云端信誉查杀 (Cloud Reputation)：

计算文件 MD5/SHA256，批量异步请求云端威胁情报。命中黑名单则直接告警；命中白名单则写入缓存。

2.3 Deep Scanner (深度扫描引擎)
指引： 只有经过 Filter 引擎后依然是“灰文件”的，才进入此模块。

特征扫描： 调用 YARA 规则引擎或其他底层查杀引擎。

资源限制 (Throttling)： 必须在低优先级线程（Background Thread）运行。Windows 下调用 SetThreadPriority 设置为最低，利用 SetFileBandwidthReservation 限制磁盘 I/O。

3. 数据模型设计参考 (Data Models)
本地缓存表 (ScanCache) 结构建议：

file_path (String, PK, Index)

file_hash (String)

last_modified (Timestamp)

scan_result (Enum: SAFE, MALICIOUS, UNKNOWN)

last_scan_time (Timestamp)

4. 触发与调度机制 (Triggers)
代码 AI 在编写 Scheduler（调度器）时，需实现以下触发逻辑：

系统空闲触发： 监听系统状态，当 CPU 空闲且无用户输入（鼠标/键盘）超过 5-10 分钟时触发。用户一旦恢复活动，立即 Pause() 扫描线程。

行为驱动触发： 暴露 RPC 或本地接口，允许 EDR 的文件驱动（Minifilter）在拦截到高危进程释放新文件时，主动向智能扫描引擎推入单个 ScanTask 进行即时扫描。

(3)请求参数和返回参数自拟一下，可以参考进程扫描的参数和返回参数，但是功能不一样不要照抄

(4)结果输出方式和之前的进程扫描一样，分为json和excel两种格式
