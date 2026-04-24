//go:build !linux && !windows

package databasescan

import (
	"context"
	"fmt"
)

func collectDatabaseRecords(ctx context.Context) ([]DatabaseRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("database scan is not supported on this platform")
}
