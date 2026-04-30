//go:build windows

package benchmark

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

func ensureElevatedPrivilege() error {
	admin, err := isWindowsAdministrator()
	if err != nil {
		return fmt.Errorf("benchmark privilege check failed: %w", err)
	}
	return validatePrivilege(runtime.GOOS, admin, 0)
}

func isWindowsAdministrator() (bool, error) {
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, err
	}
	token := windows.Token(0)
	isMember, err := token.IsMember(adminSID)
	if err != nil {
		return false, err
	}
	return isMember, nil
}
