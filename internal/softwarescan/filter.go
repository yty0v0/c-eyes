package softwarescan

import (
	"edrsystem/internal/filterutil"
	"edrsystem/internal/processscan"
)

// ApplyFilters filters software rows with requested parameters.
func ApplyFilters(rows []SoftwareInfo, params SoftwareScanParams, host processscan.HostInfo) []SoftwareInfo {
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

	filtered := make([]SoftwareInfo, 0, len(rows))
	for _, row := range rows {
		if !matchSoftwareRow(row, params) {
			continue
		}
		filtered = append(filtered, row)
	}
	return filtered
}

func matchSoftwareRow(row SoftwareInfo, params SoftwareScanParams) bool {
	if params.Name != nil {
		if row.Name == nil || !filterutil.ContainsFold(*row.Name, *params.Name) {
			return false
		}
	}
	if len(params.Version) > 0 {
		if row.Version == nil || !stringInSliceFold(*row.Version, params.Version) {
			return false
		}
	}
	if params.BinPath != nil {
		if row.BinPath == nil || !filterutil.ContainsFold(*row.BinPath, *params.BinPath) {
			return false
		}
	}
	if params.ConfigPath != nil {
		if row.ConfigPath == nil || !filterutil.ContainsFold(*row.ConfigPath, *params.ConfigPath) {
			return false
		}
	}
	return true
}
