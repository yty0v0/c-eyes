//go:build windows

package filescan

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	th32csSnapModule   = 0x00000008
	th32csSnapModule32 = 0x00000010
	maxModuleName32    = 255
)

type moduleEntry32 struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlblcntUsage uint32
	ProccntUsage uint32
	ModBaseAddr  *byte
	ModBaseSize  uint32
	HModule      windows.Handle
	SzModule     [maxModuleName32 + 1]uint16
	SzExePath    [windows.MAX_PATH]uint16
}

var (
	kernel32Module     = windows.NewLazySystemDLL("kernel32.dll")
	procModule32FirstW = kernel32Module.NewProc("Module32FirstW")
	procModule32NextW  = kernel32Module.NewProc("Module32NextW")
)

func collectProcessModules(pid int) ([]string, error) {
	if pid <= 0 {
		return nil, nil
	}
	snapshot, err := windows.CreateToolhelp32Snapshot(th32csSnapModule|th32csSnapModule32, uint32(pid))
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var entry moduleEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	ret, _, err := procModule32FirstW.Call(uintptr(snapshot), uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, err
	}

	paths := make([]string, 0, 16)
	for {
		path := windows.UTF16ToString(entry.SzExePath[:])
		if path != "" {
			paths = append(paths, path)
		}
		ret, _, _ = procModule32NextW.Call(uintptr(snapshot), uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}
	return paths, nil
}
