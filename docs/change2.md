这块主要是修改提示信息

(1)除了./c-eyes -h以外的所有提示信息参考如下内容进行修改(只是参考，你可以自行优化)，提示信息里不要写规则，注重的是清晰简介，重点写可以使用的请求参数就行，请求参数参数也可以做简单的分类来写。

主机信息异常分析： ./c-eyes hostscan --all -r 
部分主机信息异常分析： ./c-eyes hostscan --custom  <mode1>,<mode2>,...,<moden> -r 
支持六种模块的分析：
    process              进程模块
    startup              启动项模块
    scheduledtask        定时任务模块
    kernel               内核模块
    database             数据库模块
    application          Web应用模块
补充：当使用 process 模块时支持 -process-memory 启用采集进程内存样本


导出主机基本信息: ./c-eyes hostscan --all
导出部分主机基本信息: ./c-eyes hostscan --custom <mode1>,<mode2>,...,<moden> 
支持所有模块的输出：
    account              账号模块
    usergroup            用户组模块
    process              进程模块
    port                 端口模块
    startup              启动项模块
    scheduledtask        定时任务模块
    environment          环境变量模块
    kernel               内核模块
    database             数据库模块
    application          Web应用模块


Web文件信息异常分析: ./c-eyes filescan -r --all
部分Web模块文件信息异常分析: ./c-eyes filescan --custom <mode1>,<mode2>,...,<moden> -r
支持三种模块的分析：
    site                 Web站点模块
    framework            Web框架模块
    jarpackage           Jar包模块


导出Web文件基本信息：./c-eyes filescan --all
导出部分Web文件基本信息：./c-eyes filescan --custom <mode1>,<mode2>,...,<moden> 
支持三种模块的输出：
    site                 Web站点模块
    framework            Web框架模块
    jarpackage           Jar包模块


本地文件信息异常分析： ./c-eyes filescan --scan-mode <mode> -r
扫描模式选择<mode>：
    full              全盘扫描
    path <path>       指定目录扫描
    smart             智能扫描
支持 --max-targets <number> 参数限制扫描目标数量
注意：--scan-mode，--all，--custom 参数互斥不能同时使用


导出本地文件基本信息： ./c-eyes filescan --scan-mode <mode>
扫描模式选择<mode>：
    full              全盘扫描
    path <path>       指定目录扫描
    smart             智能扫描
支持 --max-targets <number> 参数限制扫描目标数量
注意：--scan-mode，--all，--custom 参数互斥不能同时使用

指定分析源进行异常分析： ./c-eyes -r -input/-file/-dir/-pid/-pname (必须指定分析源，参数五选一)


风险分析-r启用后的参数详解：
    hostscan模式下启用-r分析时可用：-yara-rules，-analysis-max-duration，-process-memory(仅启用process模块时)
    filescan模式下启用-r分析时可用：-yara-rules，-analysis-max-duration，--risk-mode，-cloud-upload 
    仅通过-r启动时可用：-yara-rules，-analysis-max-duration，--risk-mode，-cloud-upload，-process-memory(仅使用-pid/-pname时)，-input/-file/-dir/-pid/-pname

    参数描述：
        -yara-rules <path>                       yara规则路径
        -analysis-max-duration <number(s/m/h)>   分析时长限制(要加上单位，比如30s,5m,1h)
        --risk-mode <mode>                       风险分析模式
            mode: local_only(本地分析模式) / cloud_only (云分析模式) / fast(快速分析模式) / smart(智能分析模式) / deep(深度分析模式)
        -cloud-upload                            启用文件上传云分析
        -process-memory                          启用采集进程内存样本
        -input <scan.json/scan.csv/scan.xlsx>    指定已有扫描结果文件路径当作分析源
        -file <path>                             指定单独文件路径当作分析源
        -dir  <path>                             指定目录路径当作分析源，按目录下文件做风险分析
        -pid  <pid>                              指定进程 PID 当作分析源
        -pname  <process_name>                   指定进程名当作分析源


输出设置：          
  -o, --output <path>      输出路径（根据后缀识别 .json/.csv/.xlsx），默认(不启用-o)时在当前目录下输出 result*.xlsx 文件


(2)修改./c-eyes -h的提示，按如下格式写

主机信息异常分析： ./c-eyes hostscan --all -r
导出主机基本信息: ./c-eyes hostscan --all

Web文件信息异常分析: ./c-eyes filescan --all -r
导出Web文件基本信息：./c-eyes filescan --all

全盘扫描文件进行信息异常分析： ./c-eyes filescan --scan-mode full -r
导出全盘扫描的文件基本信息： ./c-eyes filescan --scan-mode full

智能扫描文件进行信息异常分析： ./c-eyes filescan --scan-mode smart -r
导出智能扫描的文件基本信息： ./c-eyes filescan --scan-mode smart

指定分析源进行异常分析： ./c-eyes -r -input/-file/-dir/-pid/-pname (必须指定分析源，参数五选一)
    -input <scan.json/scan.csv/scan.xlsx>    指定已有扫描结果文件路径当作分析源
    -file <path>                             指定单独文件路径当作分析源
    -dir  <path>                             指定目录路径当作分析源，按目录下文件做风险分析
    -pid  <pid>                              指定进程 PID 当作分析源
    -pname  <process_name>                   指定进程名当作分析源

输出设置：          
  -o, --output <path>      输出路径（根据后缀识别 .json/.csv/.xlsx），默认(不启用-o)时在当前目录下输出 result*.xlsx 文件