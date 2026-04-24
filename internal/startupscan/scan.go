package startupscan

import (
	"context"

	"edrsystem/internal/processscan"
)

var collectStartupItemsFn = collectStartupItems

// Scan collects and filters host startup information.
func Scan(ctx context.Context, params StartupScanParams) (StartupScanResult, error) {
	rows, err := collectStartupItemsFn(ctx)
	if err != nil {
		return StartupScanResult{}, err
	}

	host, _ := processscan.GetHostInfo()
	total := len(rows)
	for i := range rows {
		applyHost(&rows[i], host)
		normalizeDefaults(&rows[i])
		if params.Progress != nil {
			params.Progress(i+1, total, "collect_startup_items")
		}
	}

	filtered := ApplyFilters(rows, params, host)
	if params.Progress != nil {
		params.Progress(total, total, "complete")
	}

	return StartupScanResult{
		Total: len(filtered),
		Rows:  filtered,
	}, nil
}

func applyHost(row *StartupInfo, host processscan.HostInfo) {
	if host.DisplayIP != nil {
		row.DisplayIP = host.DisplayIP
	}
	if len(host.ExternalIPs) > 0 {
		row.ExternalIPList = append([]string(nil), host.ExternalIPs...)
		row.ExternalIP = strPtr(host.ExternalIPs[0])
	}
	if len(host.InternalIPs) > 0 {
		row.InternalIPList = append([]string(nil), host.InternalIPs...)
		row.InternalIP = strPtr(host.InternalIPs[0])
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

func normalizeDefaults(row *StartupInfo) {
	if row.HostTagList == nil {
		row.HostTagList = []string{}
	}
	if row.ExternalIPList == nil {
		row.ExternalIPList = []string{}
	}
	if row.InternalIPList == nil {
		row.InternalIPList = []string{}
	}
	if row.Xinetd == nil {
		row.Xinetd = boolPtr(false)
	}
}
