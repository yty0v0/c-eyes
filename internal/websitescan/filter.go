package websitescan

import (
	"edrsystem/internal/filterutil"
	"edrsystem/internal/processscan"
)

// ApplyFilters filters web site records with requested parameters.
func ApplyFilters(rows []WebSiteInfo, params WebSiteScanParams, host processscan.HostInfo) []WebSiteInfo {
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

	filtered := make([]WebSiteInfo, 0, len(rows))
	for _, row := range rows {
		if !matchRow(row, params) {
			continue
		}
		filtered = append(filtered, row)
	}
	return filtered
}

func matchRow(row WebSiteInfo, params WebSiteScanParams) bool {
	if params.Port != nil {
		if row.Port == nil || *row.Port != *params.Port {
			return false
		}
	}
	if params.Proto != nil {
		if row.Proto == nil || !stringInSliceFold(*row.Proto, []string{*params.Proto}) {
			return false
		}
	}
	if len(params.Type) > 0 {
		if row.Type == nil || !stringInSliceFold(*row.Type, params.Type) {
			return false
		}
	}
	if params.RootPath != nil {
		if row.Root == nil || row.Root.PhysicalPath == nil || !filterutil.ContainsFold(*row.Root.PhysicalPath, *params.RootPath) {
			return false
		}
	}
	return true
}
