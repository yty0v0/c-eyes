//go:build !linux && !windows

package webapplicationscan

import (
	"context"
	"fmt"
)

func collectWebApplications(ctx context.Context) ([]WebApplicationInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("web-application-scan is not supported on this platform")
}
