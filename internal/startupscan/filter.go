package startupscan

import (
	"edrsystem/internal/filterutil"
	"edrsystem/internal/processscan"
)

// ApplyFilters filters startup records with requested parameters.
func ApplyFilters(rows []StartupInfo, params StartupScanParams, host processscan.HostInfo) []StartupInfo {
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

	filtered := make([]StartupInfo, 0, len(rows))
	for _, row := range rows {
		if !matchRow(row, params) {
			continue
		}
		filtered = append(filtered, row)
	}
	return filtered
}

func matchRow(row StartupInfo, params StartupScanParams) bool {
	if params.Name != nil {
		if row.Name == nil || !filterutil.ContainsFold(*row.Name, *params.Name) {
			return false
		}
	}
	if len(params.InitLevel) > 0 {
		if row.InitLevel == nil || !intInSlice(*row.InitLevel, params.InitLevel) {
			return false
		}
	}
	if len(params.DefaultOpen) > 0 {
		if row.DefaultOpen == nil || !boolInSlice(*row.DefaultOpen, params.DefaultOpen) {
			return false
		}
	}
	if len(params.IsXinetd) > 0 {
		if row.Xinetd == nil || !boolInSlice(*row.Xinetd, params.IsXinetd) {
			return false
		}
	}
	if params.ShowName != nil {
		if row.ShowName == nil || !filterutil.ContainsFold(*row.ShowName, *params.ShowName) {
			return false
		}
	}
	if params.User != nil {
		if row.User == nil || !filterutil.ContainsFold(*row.User, *params.User) {
			return false
		}
	}
	if params.Enable != nil {
		if row.Enable == nil || *row.Enable != *params.Enable {
			return false
		}
	}
	if len(params.StartType) > 0 {
		if row.StartType == nil || !intInSlice(*row.StartType, params.StartType) {
			return false
		}
	}
	if params.Publisher != nil {
		if row.Publisher == nil || !filterutil.ContainsFold(*row.Publisher, *params.Publisher) {
			return false
		}
	}
	return true
}
