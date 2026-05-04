//go:build windows

package benchmark

import "context"

func scanUnixNativeBenchmark(ctx context.Context, template Template, level BaselineLevel, workingRoot string, progress func(done, total int, stage string)) (ScanResult, bool, error) {
	_ = level
	return ScanResult{}, false, nil
}
