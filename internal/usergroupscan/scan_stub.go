//go:build !windows && !linux

package usergroupscan

import (
	"context"
	"errors"
)

func collectUserGroups(ctx context.Context) ([]UserGroupInfo, error) {
	_ = ctx
	return nil, errors.New("当前操作系统不支持 user-group scan")
}
