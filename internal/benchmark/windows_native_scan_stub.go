//go:build !windows

package benchmark

import "context"

func scanWindowsNativeBenchmark(ctx context.Context, template Template, level BaselineLevel, workingRoot string, progress func(done, total int, stage string)) (ScanResult, bool, error) {
	_ = ctx
	_ = template
	_ = level
	_ = workingRoot
	_ = progress
	return ScanResult{}, false, nil
}
