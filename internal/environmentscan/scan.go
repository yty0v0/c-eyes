package environmentscan

import (
	"context"

	"edrsystem/internal/processscan"
)

var collectEnvironmentFn = collectEnvironmentEntries

// Scan collects and filters environment-variable information.
func Scan(ctx context.Context, params EnvironmentScanParams) (EnvironmentScanResult, error) {
	rows, err := collectEnvironmentFn(ctx)
	if err != nil {
		return EnvironmentScanResult{}, err
	}

	host, _ := processscan.GetHostInfo()
	total := len(rows)
	for i := range rows {
		applyHost(&rows[i], host)
		normalizeDefaults(&rows[i])
		if params.Progress != nil {
			params.Progress(i+1, total, "collect_environment")
		}
	}

	filtered := ApplyFilters(rows, params, host)
	if params.Progress != nil {
		params.Progress(total, total, "complete")
	}

	return EnvironmentScanResult{
		Total: len(filtered),
		Rows:  filtered,
	}, nil
}

func applyHost(row *EnvironmentInfo, host processscan.HostInfo) {
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

func normalizeDefaults(row *EnvironmentInfo) {
	if row.HostTagList == nil {
		row.HostTagList = []string{}
	}
	if row.ExternalIPList == nil {
		row.ExternalIPList = []string{}
	}
	if row.InternalIPList == nil {
		row.InternalIPList = []string{}
	}
	if row.SysEnv == nil {
		row.SysEnv = boolPtr(false)
	}
}
