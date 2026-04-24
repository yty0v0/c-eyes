//go:build !windows && !linux

package accountscan

import (
	"context"
	"errors"
)

func collectAccounts(ctx context.Context) ([]AccountInfo, error) {
	_ = ctx
	return nil, errors.New("当前操作系统不支持 account scan")
}
