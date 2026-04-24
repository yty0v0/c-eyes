//go:build !windows && !linux

package scheduledtaskscan

import (
	"context"
	"errors"
)

func collectScheduledTasks(ctx context.Context) ([]ScheduledTaskInfo, error) {
	_ = ctx
	return nil, errors.New("当前操作系统不支持 scheduled-task-scan")
}
