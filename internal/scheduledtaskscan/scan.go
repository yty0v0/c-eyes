package scheduledtaskscan

import (
	"context"

	"edrsystem/internal/processscan"
)

var collectScheduledTasksFn = collectScheduledTasks

// Scan collects and filters scheduled task information.
func Scan(ctx context.Context, params ScheduledTaskScanParams) (ScheduledTaskScanResult, error) {
	rows, err := collectScheduledTasksFn(ctx)
	if err != nil {
		return ScheduledTaskScanResult{}, err
	}

	host, _ := processscan.GetHostInfo()
	total := len(rows)
	for i := range rows {
		applyHost(&rows[i], host)
		normalizeDefaults(&rows[i])
		if params.Progress != nil {
			params.Progress(i+1, total, "collect_scheduled_tasks")
		}
	}

	filtered := ApplyFilters(rows, params, host)
	if params.Progress != nil {
		params.Progress(total, total, "complete")
	}

	return ScheduledTaskScanResult{
		Total: len(filtered),
		Rows:  filtered,
	}, nil
}

func applyHost(row *ScheduledTaskInfo, host processscan.HostInfo) {
	if host.DisplayIP != nil {
		row.DisplayIP = host.DisplayIP
	}
	if len(host.ExternalIPs) > 0 {
		row.ExternalIPList = append([]string(nil), host.ExternalIPs...)
	}
	if len(host.InternalIPs) > 0 {
		row.InternalIPList = append([]string(nil), host.InternalIPs...)
	}
	if host.BizGroupID != nil {
		row.BizGroupID = host.BizGroupID
	}
	if host.BizGroup != nil {
		row.BizGroup = host.BizGroup
	}
	if host.Remark != nil {
		row.Remark = host.Remark
	}
	if len(host.HostTagList) > 0 {
		row.HostTagList = append([]string(nil), host.HostTagList...)
	}
	if host.Hostname != "" {
		row.Hostname = strPtr(host.Hostname)
	}
}

func normalizeDefaults(row *ScheduledTaskInfo) {
	if row.HostTagList == nil {
		row.HostTagList = []string{}
	}
	if row.ExternalIPList == nil {
		row.ExternalIPList = []string{}
	}
	if row.InternalIPList == nil {
		row.InternalIPList = []string{}
	}
	if row.CrondOpen == nil {
		row.CrondOpen = boolPtr(false)
	}
}
