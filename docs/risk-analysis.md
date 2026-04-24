你是一个高级工具开发工程师和网络安全研究员，帮我撰写一下edr工具的风险分析部分，使用go语言来写
基本要求：
(1)风险分析分为本地匹配模式和联网查询模式
(2)本地匹配模式：把 https://github.com/VirusTotal/yara-x 这个引擎并入我的扫描器中作为本地匹配模式，使用本地嵌入式库调用的方法并入。
(3)联网查询模式：针对我的扫描结果进行联网查询，并进行风险分析。
(4)对两种模式分析的风险结果添加权重，不同风险对应不同权重，不同权重对应不同级别的风险，分为无风险，低风险，中风险，高风险，综合得分 0-20 为无风险，21-50 为低风险，51-80 为中风险，81-100 为高风险。
(5)两种分析模式对应单独的参数来调用，都支持excel表输出结果和json格式输出结果，通过我指定的扫描结果文件进行分析。
(6)目前需要分析的参数还在持续扩展阶段，你直接识别我给你的扫描结果进行分析，哪些信息需要分析就根据不同分析模式进行分析。
(7)返回参数要求如下：
1. 基础对象信息 (Target Metadata)
无论使用哪种分析模式，都需要明确“我们在分析什么”。

scan_id: 扫描任务的唯一标识符（UUID），方便溯源。

timestamp: 分析完成的时间戳。

target_type: 目标类型（如 file, process, memory_region）。

target_path: 文件绝对路径或进程的执行路径。

pid: 如果是进程扫描，记录进程 ID（文件扫描则为空或 -1）。

file_size: 文件大小（字节）。

hashes: 文件的哈希值集合（强烈建议包含 sha256，因为云端查杀主要依赖它；可选 md5, sha1）。

2. 综合风险评估结果 (Risk Assessment Results)
这是你需求中最核心的部分，直接展示最终的分析结论。

risk_level: 最终判定的风险级别（严格按照你的要求：无风险、低风险、中风险、高风险）。

risk_score: 综合计算出的具体风险分数（例如 0-100 分），用于量化定级。

analysis_mode: 本次分析使用的模式（local_only, cloud_only, hybrid）。

3. 本地引擎匹配详情 (Local YARA-X Details)
当启用了本地模式时，这部分包含 yara-x 的详细输出。

local_matched: 布尔值，标记本地是否命中规则 (true/false)。

yara_results: 命中的规则列表（数组），每个元素包含：

rule_name: 命中的 YARA 规则名称（如 APT_Tick_Malware_Gen）。

namespace: 规则所在的命名空间或分类。

tags: 规则自带的标签（如 [trojan, webshell]）。

severity: 该规则定义的严重程度权重（用于计算总分）。

matched_strings: （可选，用于取证）具体匹配到的字符串或十六进制偏移量。

4. 联网威胁情报详情 (Cloud Threat Intel Details)
当启用了联网模式时，这部分包含云端 API（如 VirusTotal）返回的分析结果。

cloud_queried: 布尔值，标记是否成功进行了云端查询。

malicious_votes: 报毒的杀软引擎数量（如 15）。

total_engines: 参与扫描的总引擎数量（如 70）。

detection_ratio: 检出率（如 15/70，这个参数对算分很有用）。

threat_labels: 云端给出的威胁标签或家族名称（如 Trojan.Win32.CobaltStrike）。

cloud_link: （可选）云端分析报告的 Web 链接，方便安全分析师点击查看详情。

💡 JSON 输出格式参考示例
当你的扫描器以 JSON 格式输出时，一条“高风险”的完整记录大概是这样的：

JSON
{
  "scan_id": "req-8f7a9b2c-1234-5678",
  "timestamp": "2026-03-17T13:35:00Z",
  "target_type": "file",
  "target_path": "C:\\Windows\\Temp\\svchost_update.exe",
  "pid": null,
  "hashes": {
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  
  "risk_assessment": {
    "analysis_mode": "hybrid",
    "risk_score": 88.5,
    "risk_level": "高风险"
  },

  "local_analysis": {
    "local_matched": true,
    "yara_results": [
      {
        "rule_name": "Suspicious_Packer_UPX",
        "tags": ["packer", "suspicious"],
        "severity": 40
      },
      {
        "rule_name": "CobaltStrike_Beacon_Memory",
        "tags": ["apt", "cobaltstrike", "memory"],
        "severity": 90
      }
    ]
  },

  "cloud_analysis": {
    "cloud_queried": true,
    "malicious_votes": 34,
    "total_engines": 72,
    "threat_labels": ["Trojan.CobaltStrike", "Win32.Malware.Gen"],
    "cloud_link": "https://www.virustotal.com/gui/file/e3b0c442.../detection"
  }
}