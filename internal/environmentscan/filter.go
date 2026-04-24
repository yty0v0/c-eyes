package environmentscan

import (
	"edrsystem/internal/filterutil"
	"edrsystem/internal/processscan"
)

// ApplyFilters filters environment-variable records with requested parameters.
func ApplyFilters(rows []EnvironmentInfo, params EnvironmentScanParams, host processscan.HostInfo) []EnvironmentInfo {
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

	filtered := make([]EnvironmentInfo, 0, len(rows))
	for _, row := range rows {
		if !matchRow(row, params) {
			continue
		}
		filtered = append(filtered, row)
	}
	return filtered
}

func matchRow(row EnvironmentInfo, params EnvironmentScanParams) bool {
	if params.Key != nil {
		if row.Key == nil || !filterutil.ContainsFold(*row.Key, *params.Key) {
			return false
		}
	}
	if params.Value != nil {
		if row.Value == nil || !filterutil.ContainsFold(*row.Value, *params.Value) {
			return false
		}
	}
	if params.User != nil {
		if row.User == nil || !filterutil.ContainsFold(*row.User, *params.User) {
			return false
		}
	}
	if len(params.SysEnv) > 0 {
		if row.SysEnv == nil || !boolInSlice(*row.SysEnv, params.SysEnv) {
			return false
		}
	}
	return true
}
