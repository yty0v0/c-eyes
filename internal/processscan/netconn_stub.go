//go:build !linux && !windows

package processscan

import "context"

func collectProcessExternalIPs(ctx context.Context) (map[int][]string, error) {
	_ = ctx
	return map[int][]string{}, nil
}
