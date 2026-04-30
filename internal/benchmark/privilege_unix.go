//go:build !windows

package benchmark

import (
	"runtime"
	"syscall"
)

func ensureElevatedPrivilege() error {
	return validatePrivilege(runtime.GOOS, false, syscall.Geteuid())
}
