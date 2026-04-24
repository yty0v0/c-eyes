package scheduledtaskscan

import (
	"time"

	"edrsystem/internal/filterutil"
	"edrsystem/internal/processscan"
)

// ApplyFilters filters scheduled task records with requested parameters.
func ApplyFilters(rows []ScheduledTaskInfo, params ScheduledTaskScanParams, host processscan.HostInfo) []ScheduledTaskInfo {
	if params.Hostname != nil {
		if !filterutil.ContainsFold(host.Hostname, *params.Hostname) {
			return nil
		}
	}
	if params.IP != nil {
		if !filterutil.HostInfoContainsIP(host, *params.IP) {
			return nil
		}
	}
	if len(params.Groups) > 0 {
		if host.BizGroupID == nil || !int64InSlice(*host.BizGroupID, params.Groups) {
			return nil
		}
	}

	filtered := make([]ScheduledTaskInfo, 0, len(rows))
	for _, row := range rows {
		if !matchRow(row, params) {
			continue
		}
		filtered = append(filtered, row)
	}
	return filtered
}

func matchRow(row ScheduledTaskInfo, params ScheduledTaskScanParams) bool {
	if len(params.User) > 0 {
		if row.User == nil || !stringContainsAnyFold(*row.User, params.User) {
			return false
		}
	}
	if params.ExecPath != nil {
		if row.ExecPath == nil || !filterutil.ContainsFold(*row.ExecPath, *params.ExecPath) {
			return false
		}
	}
	if params.Conf != nil {
		if row.Conf == nil || !filterutil.ContainsFold(*row.Conf, *params.Conf) {
			return false
		}
	}
	if params.TaskTime != nil {
		if !inDateRange(row.TaskTime, *params.TaskTime) {
			return false
		}
	}
	if len(params.TaskType) > 0 {
		if row.TaskType == nil || !stringInSliceFold(*row.TaskType, params.TaskType) {
			return false
		}
	}
	return true
}

func inDateRange(value *time.Time, dr DateRange) bool {
	if dr.From == nil && dr.To == nil {
		return true
	}
	if value == nil {
		return false
	}
	if dr.From != nil && value.Before(*dr.From) {
		return false
	}
	if dr.To != nil && value.After(*dr.To) {
		return false
	}
	return true
}

func stringContainsAnyFold(value string, needles []string) bool {
	return filterutil.ContainsAnyFold(value, needles)
}
