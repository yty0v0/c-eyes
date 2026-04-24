//go:build !windows && !linux

package processscan

import "errors"

func scanProcesses() ([]ProcessInfo, error) {
	return nil, errors.New("当前操作系统不支持 process scan")
}
