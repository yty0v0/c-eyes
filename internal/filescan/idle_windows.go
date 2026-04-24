//go:build windows

package filescan

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type lastInputInfo struct {
	cbSize uint32
	dwTime uint32
}

var (
	user32               = windows.NewLazySystemDLL("user32.dll")
	procGetLastInputInfo = user32.NewProc("GetLastInputInfo")
	kernel32Idle         = windows.NewLazySystemDLL("kernel32.dll")
	procGetTickCount64   = kernel32Idle.NewProc("GetTickCount64")
)

// WindowsIdleDetector uses GetLastInputInfo to measure idle time.
type WindowsIdleDetector struct{}

func (WindowsIdleDetector) IdleFor() (time.Duration, error) {
	var info lastInputInfo
	info.cbSize = uint32(unsafe.Sizeof(info))
	ret, _, err := procGetLastInputInfo.Call(uintptr(unsafe.Pointer(&info)))
	if ret == 0 {
		return 0, err
	}
	tick, _, _ := procGetTickCount64.Call()
	if tick == 0 {
		return 0, nil
	}
	if uint64(tick) < uint64(info.dwTime) {
		return 0, nil
	}
	idle := uint64(tick) - uint64(info.dwTime)
	return time.Duration(idle) * time.Millisecond, nil
}
