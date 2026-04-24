//go:build !windows && !linux

package portscan

import (
	"context"
	"errors"
)

func collectTCPConnectPorts(ctx context.Context) ([]PortInfo, error) {
	_ = ctx
	return nil, errors.New("当前操作系统不支持 port scan")
}

func collectTCPSYNPorts(ctx context.Context) ([]PortInfo, error) {
	_ = ctx
	return nil, errors.New("当前操作系统不支持 port scan")
}
