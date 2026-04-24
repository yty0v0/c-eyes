package portscan

import (
	"edrsystem/internal/filterutil"
	"edrsystem/internal/processscan"
)

// ApplyFilters filters port records with requested parameters.
func ApplyFilters(rows []PortInfo, params PortScanParams, host processscan.HostInfo) []PortInfo {
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

	filtered := make([]PortInfo, 0, len(rows))
	for _, row := range rows {
		if !matchRow(row, params) {
			continue
		}
		filtered = append(filtered, row)
	}
	return filtered
}

func matchRow(row PortInfo, params PortScanParams) bool {
	if len(params.Protos) > 0 {
		if row.Proto == nil {
			return false
		}
		if !protoInSlice(*row.Proto, params.Protos) {
			return false
		}
	}
	if params.Port != nil {
		if row.Port == nil || *row.Port != *params.Port {
			return false
		}
	}
	if params.BindIP != nil {
		if row.BindIP == nil || !filterutil.ContainsFold(*row.BindIP, *params.BindIP) {
			return false
		}
	}
	if params.ProcessName != nil {
		if row.ProcessName == nil || !filterutil.ContainsFold(*row.ProcessName, *params.ProcessName) {
			return false
		}
	}
	return true
}

func protoInSlice(proto string, filters []string) bool {
	target := normalizeProto(proto)
	for _, item := range filters {
		if target == normalizeProto(item) {
			return true
		}
	}
	return false
}
