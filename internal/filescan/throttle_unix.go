//go:build !windows

package filescan

import "syscall"

func applyThrottling() {
	_ = syscall.Setpriority(syscall.PRIO_PROCESS, 0, 10)
}
