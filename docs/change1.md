你是一个高级工具开发工程师和网络安全研究员，帮我按需求重构一下这个edr工具，编码使用utf-8。

基本要求：

(1)hostscan模块设计
    把如下的功能合并成 hostscan（主机信息扫描）的附加参数（account,usergroup,process,port,startup,scheduledtask,environment,kernel,database,application）。
    account scan            扫描系统账户
    user-group scan         扫描用户组
    process scan            扫描进程
    port-scan               扫描监听端口
    startup-scan            扫描启动项
    scheduled-task-scan     扫描计划任务
    environment-scan        扫描环境变量
    kernel-scan             扫描内核信息
    database-scan           扫描数据库
    web-application-scan    扫描 Web 应用

    调用方式分为单模块，多模块，所有模块。添加--custom参数指定模块使用默认配置。添加all参数指令默认加载所有模块的默认配置。
    单模块调用示例：./c-eyes hostscan --custom account
    多模块调用示例：./c-eyes hostscan --custom account,process
    所有模块调用示例：./c-eyes hostscan --all    (添加all参数，指令默认加载所有模块的默认配置，自动化获取主机的这些信息最后结果去重输出一份整体的扫描结果)

    请求参数处理：多模块扫描和all扫描时请求参数为所有主机信息扫描模块都有的请求参数，单个模块扫描时请求参数就是该模块所有的请求参数。

    扫描结果处理：多模块和all扫描时，不同模块的扫描返回结果可能有相同的参数，那么这些参数就重复了，需要去重。最终输出一份汇总并去重的扫描结果就行。


(2)filescan模块设计
    把如下这几个功能整合成filescan（文件信息扫描模块）的附加参数（site,framework,jarpackage）。
    web-site-scan           扫描 Web 站点
    web-framework-scan      扫描 Web 框架
    jar-package-scan        扫描 Jar 包

    调用方式分为单模块，多模块，所有模块。添加--custom参数指定模块使用默认配置。添加all参数指令默认加载所有模块的默认配置。
    单模块调用示例：./c-eyes filescan --custom site
    多模块调用示例：./c-eyes filescan --custom site,framework
    所有模块调用示例：./c-eyes filescan --all

    请求参数处理：多模块扫描和all扫描时请求参数为所有web信息扫描模块都有的请求参数，单个模块扫描时请求参数就是该模块所有的请求参数。

    扫描结果处理：多模块和all扫描时，不同模块的扫描返回结果可能有相同的参数，那么这些参数就重复了，需要去重。最终输出一份汇总并去重的扫描结果就行。

    web扫描：当启用site,framework,jarpackage这三种扫描模式时，不支持三种文件扫描模式的选择（full，path，smart）
    

(3)riskanalyze风险分析修改
    把riskanalyze风险分析模块做成全局参数 -r, --riskanalyze，使用方式有两种：

    方法一：可以直接通过指定的excel/json/csv类型的文件路径，通过读取文件里收集到的信息进行风险分析，根据文件后缀自动识别文件，最终输出对应格式的分析结果。
    示例1：./c-eyes --riskanalyze -file hosts.xlsx
    示例2：./c-eyes -r -file hosts.json

    方法二：如果是通过 hostscan，filescan 这两种模块启动的分析，此时作为这两种模块的附加参数，那就是先进行完对应的信息扫描模块，把扫到的信息直接给风险分析模块进行分析，最终只输出分析的结果即可。
    示例1：./c-eyes hostscan --custom account -r 
    示例2：./c-eyes filescan -r
    示例3：./c-eyes filescan --mode smart -r   

    补充：原有风险分析模块下的请求参数都保留，启动风险分析模块的启动参数以后这些参数都可以正常使用（hostscan 只能使用有关本地风险分析的参数，因为 hostscan 这个模块默认且只能使用yara-x本地风险分析（local_only模式）），filescan可以选用五种分析模式，默认使用smart智能分析。


(4)修改：把文件扫描的三种模式都添加到-h的提示信息里，并对每种扫描模式分别给出提示信息，风险扫描的五种扫描模式也一样，每个都给出对应的提示信息。


(5)你要验证一下，改动以后剩下两个大模块，主机信息扫描，文件扫描 这两个。其它的各种功能都已经归到这两个大模块里。


(6)去掉所有扫描模块指定输出excel或者json的功能，每个模块都有单独的这个参数不如直接改成全局的，在./c-eyes 再添加一个全局参数-o, --output，支持输出json，csv或excel三种格式的结果，execl的输出需要指定路径，默认输出json。


(7)如果请求参数使用不对进行对应错误的提示。