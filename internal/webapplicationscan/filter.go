package webapplicationscan

import (
	"edrsystem/internal/filterutil"
	"edrsystem/internal/processscan"
)

// ApplyFilters filters web application records with requested parameters.
func ApplyFilters(rows []WebApplicationInfo, params WebApplicationScanParams, host processscan.HostInfo) []WebApplicationInfo {
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

	filtered := make([]WebApplicationInfo, 0, len(rows))
	for _, row := range rows {
		if !matchRow(row, params) {
			continue
		}
		filtered = append(filtered, row)
	}
	return filtered
}

func matchRow(row WebApplicationInfo, params WebApplicationScanParams) bool {
	if len(params.Version) > 0 {
		if row.Version == nil || !stringInSliceFold(*row.Version, params.Version) {
			return false
		}
	}
	if params.AppName != nil {
		if row.AppName == nil || !filterutil.ContainsFold(*row.AppName, *params.AppName) {
			return false
		}
	}
	if params.RootPath != nil {
		if row.RootPath == nil || !filterutil.ContainsFold(*row.RootPath, *params.RootPath) {
			return false
		}
	}
	if params.WebRoot != nil {
		if row.WebRoot == nil || !filterutil.ContainsFold(*row.WebRoot, *params.WebRoot) {
			return false
		}
	}
	if len(params.ServerName) > 0 {
		if row.ServerName == nil || !stringContainsAnyFold(*row.ServerName, params.ServerName) {
			return false
		}
	}
	if params.DomainName != nil {
		if row.DomainName == nil || !filterutil.ContainsFold(*row.DomainName, *params.DomainName) {
			return false
		}
	}
	return true
}
