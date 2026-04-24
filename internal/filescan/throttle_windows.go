//go:build windows

package filescan

import "golang.org/x/sys/windows"

var threadPriorityLowest = int32(-2)

var (
	kernel32Proc          = windows.NewLazySystemDLL("kernel32.dll")
	procGetCurrentThread  = kernel32Proc.NewProc("GetCurrentThread")
	procSetThreadPriority = kernel32Proc.NewProc("SetThreadPriority")
)

func applyThrottling() {
	handle, _, _ := procGetCurrentThread.Call()
	if handle == 0 {
		return
	}
	_, _, _ = procSetThreadPriority.Call(handle, uintptr(threadPriorityLowest))
}
