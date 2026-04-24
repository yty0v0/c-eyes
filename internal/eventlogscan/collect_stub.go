//go:build !windows && !linux

package eventlogscan

import (
	"context"
	"fmt"
)

func collectPlatformEvents(ctx context.Context, params QueryParams) ([]rawEvent, error) {
	_ = ctx
	_ = params
	return nil, fmt.Errorf("eventlog collection is not supported on this operating system")
}
