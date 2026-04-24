//go:build !linux && !windows

package kernelscan

import (
	"context"
	"fmt"
)

type unsupportedKernelScanProvider struct{}

func defaultKernelScanProvider() KernelScanProvider {
	return unsupportedKernelScanProvider{}
}

func (unsupportedKernelScanProvider) Collect(ctx context.Context) ([]KernelModuleInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("kernel scan is not supported on this platform")
}
