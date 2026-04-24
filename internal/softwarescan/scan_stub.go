//go:build !linux && !windows

package softwarescan

import "context"

func collectSoftware(ctx context.Context) ([]SoftwareInfo, error) {
	_ = ctx
	return []SoftwareInfo{}, nil
}
