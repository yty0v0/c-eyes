package filescan

import (
	"context"
	"time"
)

// RecentChangeCollector gathers recently modified executable/script files.
type RecentChangeCollector struct {
	Window time.Duration
}

func (c RecentChangeCollector) Collect(ctx context.Context, params FileScanParams) ([]ScanTask, error) {
	window := c.Window
	if window <= 0 {
		window = 24 * time.Hour
	}
	since := time.Now().Add(-window)
	tasks, ok, err := collectRecentPlatform(ctx, params, since)
	if err != nil {
		return nil, err
	}
	if ok && len(tasks) > 0 {
		return dedupeTasks(tasks), nil
	}
	return collectRecentFallback(ctx, params, since)
}
