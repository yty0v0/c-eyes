//go:build windows

package processscan

import (
	"sort"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wtsCurrentServerHandle uintptr = 0
	wtsWinStationName      uint32  = 6
)

var (
	modWTS                         = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformation = modWTS.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory              = modWTS.NewProc("WTSFreeMemory")
)

func scanProcesses() ([]ProcessInfo, error) {
	//创建进程快照，供枚举进程
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	visible := collectVisibleWindowPIDs()
	sessionNames := make(map[uint32]*string)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	//读取第一个进程，并把内容写入entry结构体
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil, err
	}

	processes := make([]ProcessInfo, 0, 256)
	for {
		pid := int(entry.ProcessID)
		ppid := int(entry.ParentProcessID)
		name := windows.UTF16ToString(entry.ExeFile[:])

		proc := ProcessInfo{
			PID:  intPtr(pid),
			PPID: intPtr(ppid),
			Name: nullableString(name, ""),
		}

		//给当前进程结构体补充部分 Windows 细节信息，一部分通过pid打开进程句柄获取，一部分通过pid调用api获取
		fillWindowsDetails(&proc, uint32(pid), visible, sessionNames)

		processes = append(processes, proc)

		//枚举进程时读取下一个条目
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			if err == syscall.ERROR_NO_MORE_FILES {
				break
			}
			break
		}
	}

	return processes, nil
}

func fillWindowsDetails(proc *ProcessInfo, pid uint32, visible map[uint32]bool, sessionNames map[uint32]*string) {
	//打开进程句柄
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return
	}
	defer windows.CloseHandle(handle)

	//读取进程可执行路径，并通过路径获取文件信息(进程可执行文件的MD5值，大小，和版本)
	if path := queryProcessImage(handle); path != nil {
		proc.Path = path
		if md5sum, err := fileMD5(*path); err == nil {
			proc.Md5 = md5sum
		}
		if size, err := fileSize(*path); err == nil {
			proc.Size = size
		}
		if version, desc := fileVersionInfo(*path); version != nil {
			proc.Version = version
			proc.Description = desc
		} else if desc != nil {
			proc.Description = desc
		}
	}

	//读取进程启动时间
	if start := getProcessStartTime(handle); start != nil {
		proc.StartTime = start
	}

	//读取进程会话ID
	if sid := getSessionID(pid); sid != nil {
		proc.SessionID = sid
		if name := sessionNameForID(uint32(*sid), sessionNames); name != nil {
			proc.SessionName = name
		}
	}

	//读取进程用户信息(用户名，用户id，用户组)
	if uname, uid, groups := getProcessUserAndGroups(handle); uname != nil {
		proc.Uname = uname
		proc.UID = uid
		if len(groups) > 0 {
			proc.Groups = groups
		}
	}

	//读取进程类型
	if typ := deriveProcessType(pid, proc.SessionID, visible); typ != nil {
		proc.Type = typ
	}
}

func queryProcessImage(handle windows.Handle) *string {
	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return nil
	}
	path := windows.UTF16ToString(buf[:size])
	if path == "" {
		return nil
	}
	return strPtr(path)
}

func getProcessStartTime(handle windows.Handle) *time.Time {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return nil
	}
	start := time.Unix(0, creation.Nanoseconds())
	return timePtr(start)
}

func getSessionID(pid uint32) *int {
	var session uint32
	if err := windows.ProcessIdToSessionId(pid, &session); err != nil {
		return nil
	}
	val := int(session)
	return &val
}

func sessionNameForID(sessionID uint32, cache map[uint32]*string) *string {
	if name, ok := cache[sessionID]; ok {
		return name
	}
	name := querySessionName(sessionID)
	cache[sessionID] = name
	return name
}

func querySessionName(sessionID uint32) *string {
	var buffer uintptr
	var returned uint32

	r1, _, _ := procWTSQuerySessionInformation.Call(
		wtsCurrentServerHandle,
		uintptr(sessionID),
		uintptr(wtsWinStationName),
		uintptr(unsafe.Pointer(&buffer)),
		uintptr(unsafe.Pointer(&returned)),
	)
	if r1 == 0 || buffer == 0 || returned == 0 {
		return nil
	}
	defer procWTSFreeMemory.Call(buffer)

	name := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(buffer)))
	if name == "" {
		return nil
	}
	return strPtr(name)
}

func deriveProcessType(pid uint32, sessionID *int, visible map[uint32]bool) *int {
	if sessionID != nil && *sessionID == 0 {
		return intPtr(3)
	}
	if visible[pid] {
		return intPtr(1)
	}
	if sessionID != nil {
		return intPtr(2)
	}
	return nil
}

func collectVisibleWindowPIDs() map[uint32]bool {
	//记录是可见窗口的 PID
	visible := make(map[uint32]bool)

	//回调函数指针
	callback := syscall.NewCallback(func(hwnd windows.HWND, lparam uintptr) uintptr {
		//判断窗口是否可见
		if windows.IsWindowVisible(hwnd) {
			var pid uint32

			//拿到可见窗口所属进程 PID
			_, _ = windows.GetWindowThreadProcessId(hwnd, &pid)
			if pid != 0 {
				visible[pid] = true
			}
		}

		//继续枚举下一个窗口
		return 1
	})

	//枚举当前系统中的所有顶层窗口
	_ = windows.EnumWindows(callback, nil)

	return visible
}

func getProcessUserAndGroups(handle windows.Handle) (*string, *int64, []string) {
	var token windows.Token
	if err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err != nil {
		return nil, nil, nil
	}
	defer token.Close()

	uname, uid := tokenUser(token)
	groups := tokenGroups(token)
	return uname, uid, groups
}

func tokenUser(token windows.Token) (*string, *int64) {
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, nil
	}

	name, domain, err := lookupAccountSid(user.User.Sid)
	if err != nil {
		return nil, nil
	}
	full := name
	if domain != "" {
		full = domain + "\\" + name
	}
	sidStr := user.User.Sid.String()

	uid := int64(0)
	if sidStr != "" {
		uid = sidHash(sidStr)
	}
	return strPtr(full), int64Ptr(uid)
}

func tokenGroups(token windows.Token) []string {
	groups, err := token.GetTokenGroups()
	if err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	for _, group := range groups.AllGroups() {
		if group.Sid == nil {
			continue
		}
		name, domain, err := lookupAccountSid(group.Sid)
		if err != nil || name == "" {
			continue
		}
		full := name
		if domain != "" {
			full = domain + "\\" + name
		}
		seen[full] = struct{}{}
	}

	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func lookupAccountSid(sid *windows.SID) (string, string, error) {
	var nameLen uint32
	var domainLen uint32
	var use uint32

	err := windows.LookupAccountSid(nil, sid, nil, &nameLen, nil, &domainLen, &use)
	if err != nil && err != syscall.ERROR_INSUFFICIENT_BUFFER {
		return "", "", err
	}
	nameBuf := make([]uint16, nameLen)
	domainBuf := make([]uint16, domainLen)
	if err := windows.LookupAccountSid(nil, sid, &nameBuf[0], &nameLen, &domainBuf[0], &domainLen, &use); err != nil {
		return "", "", err
	}

	return windows.UTF16ToString(nameBuf), windows.UTF16ToString(domainBuf), nil
}

func sidHash(sid string) int64 {
	// Simple hash to provide stable numeric uid representation on Windows.
	var hash int64 = 1469598103934665603
	for _, r := range sid {
		hash ^= int64(r)
		hash *= 1099511628211
	}
	if hash < 0 {
		hash = -hash
	}
	return hash
}

func fileVersionInfo(path string) (*string, *string) {
	var handle windows.Handle
	size, err := windows.GetFileVersionInfoSize(path, &handle)
	if err != nil || size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil {
		return nil, nil
	}

	lang, code := getTranslation(buf)
	queryBase := "\\StringFileInfo\\" + lang + code + "\\"

	version := queryVerValue(buf, queryBase+"ProductVersion")
	if version == nil {
		version = queryVerValue(buf, queryBase+"FileVersion")
	}
	desc := queryVerValue(buf, queryBase+"FileDescription")
	return version, desc
}

func getTranslation(buf []byte) (string, string) {
	var transPtr unsafe.Pointer
	var transLen uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), "\\VarFileInfo\\Translation", unsafe.Pointer(&transPtr), &transLen); err != nil {
		return "0409", "04B0"
	}
	if transLen < 4 || transPtr == nil {
		return "0409", "04B0"
	}
	translations := (*[2]uint16)(transPtr)
	return formatHex(translations[0]), formatHex(translations[1])
}

func queryVerValue(buf []byte, path string) *string {
	var ptr unsafe.Pointer
	var length uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buf[0]), path, unsafe.Pointer(&ptr), &length); err != nil {
		return nil
	}
	if ptr == nil {
		return nil
	}
	value := windows.UTF16PtrToString((*uint16)(ptr))
	if value == "" {
		return nil
	}
	return strPtr(value)
}

func formatHex(value uint16) string {
	const hex = "0123456789ABCDEF"
	return string([]byte{
		hex[(value>>12)&0xF],
		hex[(value>>8)&0xF],
		hex[(value>>4)&0xF],
		hex[value&0xF],
	})
}
