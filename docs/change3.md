(1)修改c-eyes -h的提示，按如下格式写：
NAME:
    c-eyes -  Endpoint Security Detection Tool

USAGE:
    c-eyes [global options] command [command options] [arguments...] 

DESCRIPTION:
    Endpoint Security Detection Tool

COMMANDS:
    hostscan    host information module
    filescan    document information module

GLOBAL OPTIONS:
    -o  Output path (identified by extensions .json/.csv/.xlsx)
    -r, --riskanalysis  Enable risk analysis,When not using the hostscan and filescan modules, enter the specified analysis source exception analysis mode. For detailed methods, check via c-eyes -r -h.
    -h, --help  show help


(2)修改c-eyes hostscan -h的提示，按如下格式写：
NAME:
    c-eyes hostscan -  Run a hostscan task

USAGE:
    c-eyes hostscan [command options] [arguments...]

OPTIONS:
    --custom <mode1>,<mode2>,...,<moden>    Specify the scan or analysis module
        mode(Information scanning supported modules): account,usergroup,process,port,startup,scheduledtask,environment,kernel,database,application
        mode(Risk analysis support module):process,startup,scheduledtask,kernel,database,application
        Supplement: The request filtering parameters for one or multiple modules can be viewed in this format: ./c-eyes hostscan --custom <mode> -h

OPTIONS(only -r enable can use):
    -yara-rules <path>               Yara rule path
    -analysis-max-duration <number>  Analysis duration limit (add units, such as 30s, 5m, 1h)
    -process-memory                  Enable collection of process memory samples (supported when using the process module)


(3)修改c-eyes filescan -h的提示，按如下格式写：
NAME:
    c-eyes filescan -  Run a filescan task

USAGE:
    c-eyes filescan [command options] [arguments...]

OPTIONS:
    --custom <mode1>,<mode2>,...,<moden>    Specify the scan or analysis module
        mode: site,framework,jarpackage
        Supplement: The request filtering parameters for one or multiple modules can be viewed in this format: ./c-eyes filescan --custom <mode> -h
    --scan-mode                             Scan mode selection,optional mode: full / path <path> / smart ,and it cannot be used simultaneously with the --custom parameter (mutually exclusive)
    
OPTIONS(only -r enable can use):
    -yara-rules <path>               Yara rule path
    -analysis-max-duration <number>  Analysis duration limit (add units, such as 30s, 5m, 1h)
    -cloud-upload                    Enable file upload cloud analysis
    --risk-mode <mode>               Risk analysis mode, mode: local_only / cloud_only  / fast / smart / deep
    --max-targets <number>           Limit the number of scan targets
    

(4)修改c-eyes -r -h的提示信息，按如下格式写：
NAME:
    c-eyes -r -  Designated analysis source for anomaly analysis

USAGE:
    ./c-eyes -r -input/-file/-dir/-pid/-pname  ((Analysis source must be specified, choose one of the five specified parameters))

OPTIONS:
    -yara-rules <path>                        Yara rule path
    -analysis-max-duration <number>           Analysis duration limit (add units, such as 30s, 5m, 1h)
    -cloud-upload                             Enable file upload cloud analysis
    -process-memory                           Enable collection of process memory samples (only supported when using - pid/- pname)
    --risk-mode <mode>                        Risk analysis mode, mode: local_only / cloud_only  / fast / smart / deep
    -input <scan.json/scan.csv/scan.xlsx>     Specify the path of the existing scan result file as an analysis source
    -file <path>                              Specify the path of a single file as an analysis source
    -dir  <path>                              Specify the path of a directory as an analysis source, and perform risk analysis on the files in the directory
    -pid  <pid>                               Specify the PID of the process as an analysis source
    -pname  <process_name>                    Specify the process name as an analysis source
    

(5)去掉c-eyes hostscan -r -h 和 c-eyes filescan -r -h的提示信息，现在我已经都整合到c-eyes hostscan -h和c-eyes filescan -h里了，所以就多余了，不用再在c-eyes hostscan -r -h 和 c-eyes filescan -r -h看了


(6)通过./c-eyes hostscan --custom account,usergroup -h这种形式查看模块的提示信息的地方，查看的题信息只显示选用的一个或多个模块的请求过滤参数即可，多个的时候还是走取交集的逻辑，格式参考一下上面的改动，只写OPTIONS的部分就行，要英文的。记住是查看所有这种形式模块的地方都这么改(--custom)。