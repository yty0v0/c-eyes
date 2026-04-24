//go:build !linux && !windows

package environmentscan

import (
	"context"
	"fmt"
)

func collectEnvironmentEntries(ctx context.Context) ([]EnvironmentInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("environment scan is not supported on this platform")
}
