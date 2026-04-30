//go:build windows

package benchmark

import "context"

func scanUnixNativeBenchmark(ctx context.Context, template Template, workingRoot string, progress func(done, total int, stage string)) (ScanResult, bool, error) {
	return ScanResult{}, false, nil
}
