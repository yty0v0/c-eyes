//go:build !windows && !linux

package startupscan

import (
	"context"
	"errors"
)

func collectStartupItems(ctx context.Context) ([]StartupInfo, error) {
	_ = ctx
	return nil, errors.New("当前操作系统不支持 startup scan")
}
