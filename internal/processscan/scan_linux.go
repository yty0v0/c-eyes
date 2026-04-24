//go:build linux

package processscan

import (
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func scanProcesses() ([]ProcessInfo, error) {
	//读取 /proc 目录内容
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	processes := make([]ProcessInfo, 0, len(entries))

	//枚举每个目录名，只处理“纯数字”的目录（PID）(/proc 目录里只有名字是纯数字的子目录才代表进程 PID，其它名字是系统信息目录)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}

		//对每个 PID 调用 readProcProcess(pid)去读取信息
		proc, err := readProcProcess(pid)
		if err != nil {
			continue
		}
		processes = append(processes, proc)
	}

	return processes, nil
}

func readProcProcess(pid int) (ProcessInfo, error) {
	//拼出某个进程在 /proc/<pid>/ 下的关键文件路径，用于后面读取进程信息
	statPath := filepath.Join("/proc", strconv.Itoa(pid), "stat")
	statusPath := filepath.Join("/proc", strconv.Itoa(pid), "status")
	cmdlinePath := filepath.Join("/proc", strconv.Itoa(pid), "cmdline")
	exePath := filepath.Join("/proc", strconv.Itoa(pid), "exe")

	//读进程基础状态，解析失败说明这个进程暂时读不到（因为这块是核心必需信息所以做了err的处理）
	statData, err := os.ReadFile(statPath)
	if err != nil {
		return ProcessInfo{}, err
	}
	//读取的是进程的基础状态信息（比如 pid、ppid、进程状态、启动 tick 等）
	stat, err := parseProcStat(string(statData))
	if err != nil {
		return ProcessInfo{}, err
	}

	//读取的是更人类可读的状态信息，包含 UID/GID、进程名、线程数等
	statusData, _ := os.ReadFile(statusPath)
	status := parseProcStatus(string(statusData))

	//读取的是启动命令行参数，以 \0 分隔。解析后得到 startArgs
	cmdline, _ := os.ReadFile(cmdlinePath)
	cmdlineStr := parseCmdline(cmdline)

	//这是一个符号链接，指向进程的可执行文件路径。如果读不到，就用 stat.Comm（进程名）做兜底
	exe, _ := os.Readlink(exePath)
	if exe == "" {
		exe = stat.Comm
	}

	//根据 /proc/<pid>/stat 的启动 tick 计算进程真实启动时间
	var startTime *time.Time
	if stat.StartTicks > 0 {
		if boot, err := getBootTime(); err == nil {
			ticks := float64(stat.StartTicks)
			hz := getClockTicks()
			secs := int64(ticks / hz)
			t := boot.Add(time.Duration(secs) * time.Second)
			startTime = timePtr(t)
		}
	}

	proc := ProcessInfo{
		PID:       intPtr(pid),
		PPID:      intPtr(stat.PPID),
		Name:      nullableString(status.Name, stat.Comm),
		Path:      nullableString(exe, ""),
		StartArgs: nullableString(cmdlineStr, ""),
		State:     nullableString(stat.State, ""),
		StartTime: startTime,
		UID:       status.UID,
		GID:       status.GID,
		Uname:     status.Uname,
		Gname:     status.Gname,
		Root:      status.Root,
		TTY:       readTTY(pid),
	}

	//拿到可执行文件路径后，补充“文件指纹 + 包信息
	if exe != "" {
		//计算可执行文件的 MD5，成功就填 proc.Md5
		if sum, err := fileMD5(exe); err == nil {
			proc.Md5 = sum
		}
		//在 dpkg/rpm 数据库里查这个路径属于哪个包，查到就填 packageName / packageVersion，并把 installByPm 设为 true
		if pkg, ver, ok := lookupPackageForPath(exe); ok {
			proc.PackageName = strPtr(pkg)
			proc.PackageVersion = strPtr(ver)
			proc.InstallByPm = boolPtr(true)
		}
	}

	return proc, nil
}
