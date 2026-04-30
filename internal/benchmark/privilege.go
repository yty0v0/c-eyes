package benchmark

import "fmt"

func validatePrivilege(goos string, isWindowsAdmin bool, euid int) error {
	if normalizeLowerTrim(goos) == "windows" {
		if !isWindowsAdmin {
			return fmt.Errorf("benchmark requires administrator privilege on Windows")
		}
		return nil
	}

	if euid != 0 {
		return fmt.Errorf("benchmark requires root privilege on Linux-family systems")
	}
	return nil
}
