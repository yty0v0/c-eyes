package portscan

import (
	"context"

	"edrsystem/internal/processscan"
)

var (
	collectTCPConnectPortsFn = collectTCPConnectPorts
	collectTCPSYNPortsFn     = collectTCPSYNPorts
)

// Scan collects and filters host port information.
func Scan(ctx context.Context, params PortScanParams) (PortScanResult, error) {
	mode := normalizeMode(params.Mode)

	var (
		rows []PortInfo
		err  error
	)
	switch mode {
	case ScanModeTCPSYN:
		rows, err = collectTCPSYNPortsFn(ctx)
	default:
		rows, err = collectTCPConnectPortsFn(ctx)
	}
	if err != nil {
		return PortScanResult{}, err
	}

	host, _ := processscan.GetHostInfo()
	total := len(rows)
	for i := range rows {
		applyHost(&rows[i], host)
		normalizeDefaults(&rows[i])
		if params.Progress != nil {
			params.Progress(i+1, total, "collect_ports")
		}
	}

	filtered := ApplyFilters(rows, params, host)
	if params.Progress != nil {
		params.Progress(total, total, "complete")
	}

	return PortScanResult{
		Total: len(filtered),
		Rows:  filtered,
	}, nil
}

func applyHost(row *PortInfo, host processscan.HostInfo) {
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
}

func normalizeDefaults(row *PortInfo) {
	if row.HostTagList == nil {
		row.HostTagList = []string{}
	}
	if row.ExternalIPList == nil {
		row.ExternalIPList = []string{}
	}
	if row.InternalIPList == nil {
		row.InternalIPList = []string{}
	}
	if row.Status == nil {
		row.Status = intPtr(-1)
	}
}
