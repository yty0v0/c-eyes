本地文件信息异常分析： c-eyes filescan --scan-mode <mode> -r
扫描模式选择<mode>：
    full              全盘扫描
    path <path>       指定目录扫描
    smart             智能扫描
支持 --max-targets <number> 参数限制扫描目标数量
注意：--scan-mode，--all，--custom 参数互斥不能同时使用


导出本地文件基本信息： c-eyes filescan --scan-mode <mode>
扫描模式选择<mode>：
    full              全盘扫描
    path <path>       指定目录扫描
    smart             智能扫描
支持 --max-targets <number> 参数限制扫描目标数量
注意：--scan-mode，--all，--custom 参数互斥不能同时使用

把上面这两个单独的smart扫描模式去掉。把smart智能扫描作为参数并入full和path模式，就是开启full和path模式以后可以通过启用smart参数来开启full或path模式下智能扫描。然后这个智能扫描如何做你自己来想想，可以优先扫高危和敏感目录。