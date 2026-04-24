//go:build !windows

package riskanalysis

import "fmt"

// CaptureProcessMemory is unsupported on non-Windows platforms in this build.
func CaptureProcessMemory(pid int, maxBytes int) ([]byte, error) {
	_ = pid
	_ = maxBytes
	return nil, fmt.Errorf("process memory capture is only supported on windows")
}
