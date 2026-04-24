一、 基础元数据 (Basic Metadata)
这是文件的外在属性，采集成本极低，是后端进行基础过滤和检索的核心。

file_path (绝对路径): 完整路径（包含驱动器号或根目录）。

file_name (文件名): 包含扩展名。

file_size_bytes (文件大小): 字节数。

timestamps (时间戳): 必须采集创建时间（C-Time）、修改时间（M-Time）、最后访问时间（A-Time）。注意精度要到毫秒级，后端会用它来分析“时间戳伪造”。

attributes (文件属性): * Windows: 是否为隐藏文件、系统文件、只读文件。

Linux: 属主 (Owner)、属组 (Group)、权限掩码 (如 0755，特别要注意是否包含 s 位提权标志)。

二、 密码学指纹 (Cryptographic Hashes)
文件的唯一身份标识，用于后端直接碰撞威胁情报（CTI）黑白名单。

sha256: 必需。当前最主流、防碰撞能力最强的 Hash。

三、 身份与数字签名 (Authenticode & Signatures)
后端降低误报率（放行白文件）和发现高级伪装（如假冒系统组件）的最重要依据。

is_signed (是否有签名): Boolean。

signature_valid (签名是否有效): Boolean。检查签名证书是否过期、是否被吊销、是否能追溯到受信任的根证书。

signer_subject (签名者信息): 如 Microsoft Corporation 或 Google LLC。

certificate_thumbprint (证书指纹): 用于后端追踪是不是某个被黑客盗用的特定合法证书签发的文件。

四、 二进制深度结构特征 (Binary Internals - 针对 PE/ELF 等可执行文件)
这是后期后端规则引擎（如 YARA）和机器学习模型进行启发式分析的“核心燃料”。

magic_bytes (文件头标志): 读取文件前几个字节（如 4D 5A 代表 PE，7F 45 4C 46 代表 ELF），无视后缀名，记录真实的底层文件格式。

imphash (导入表哈希): 极其重要。将可执行文件调用的所有 API 名字连起来算一个 Hash。后端用它来追踪 APT 组织的特有开发习惯。

imported_libraries (导入库及 API 列表): * 采集它加载了哪些 DLL/SO 文件（如 kernel32.dll, ws2_32.dll）。

采集它调用了哪些敏感 API（如 VirtualAlloc, CreateRemoteThread）。

sections_info (节区信息): 采集每个节（如 .text, .data, .rsrc）的名称、大小和局部的节区熵值。

version_info (版本资源信息): 提取 PE 文件内置的 OriginalFilename (原始文件名) 和 FileDescription (文件描述)。后端会比对：如果文件名叫 svchost.exe，但内置原始文件名叫 mimikatz.exe，那就是铁板钉钉的木马。

五、 环境与上下文依赖 (Contextual Info)
文件落盘时的特殊标记。

motw_zone_id (网络来源标记): （仅限 Windows） 检查并读取文件的备用数据流（Alternate Data Stream）Zone.Identifier。采集该文件是否是从浏览器或邮件客户端下载的，以及下载它的原始 URL（如果提取得到的话）。

给代码 AI 的 JSON 结构示例
你可以直接把以下结构发给代码 AI，让它帮你生成对应语言（Go/C++/Rust）的数据采集结构体（Struct）：

JSON
{
  "basic_info": {
    "path": "C:\\Windows\\Temp\\update_v2.exe",
    "name": "update_v2.exe",
    "size": 1048576,
    "creation_time": "2026-03-05T10:00:00.000Z",
    "modification_time": "2026-03-05T10:00:00.000Z",
    "attributes": ["HIDDEN", "SYSTEM"]
  },
  "hashes": {
    "sha256": "4fd0101ea...",
    "imphash": "f34d5f2d4577ed6d9ceec516c1f5a744"
  },
  "signature": {
    "is_signed": true,
    "is_valid": false,
    "subject": "Unknown Publisher",
    "thumbprint": "A1B2C3D4..."
  },
  "pe_info": {
    "magic": "MZ",
    "sections": [
      { "name": ".text", "size": 512000, "entropy": 6.1 },
      { "name": ".upx1", "size": 409600, "entropy": 7.9 } 
    ],
    "imports": [
      { "dll": "kernel32.dll", "functions": ["VirtualAllocEx", "WriteProcessMemory"] }
    ],
    "original_filename": "payload_x86.exe"
  },
  "context": {
    "has_motw": true,
    "download_url": "http://malicious-site.com/drop.exe"
  }
}
