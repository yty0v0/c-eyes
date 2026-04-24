//go:build !linux && !windows

package websitescan

import (
	"context"
	"fmt"
)

func collectWebSites(ctx context.Context) ([]WebSiteInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("web-site-scan is not supported on this platform")
}
