package databasescan

import (
	"edrsystem/internal/filterutil"
	"edrsystem/internal/processscan"
)

// ApplyFilters filters database records with requested parameters.
func ApplyFilters(rows []DatabaseRecord, params DatabaseScanParams, host processscan.HostInfo) []DatabaseRecord {
	if params.Hostname != nil && !filterutil.ContainsFold(host.Hostname, *params.Hostname) {
		return nil
	}
	if params.IP != nil && !filterutil.HostInfoContainsIP(host, *params.IP) {
		return nil
	}
	if len(params.Groups) > 0 {
		if host.BizGroupID == nil || !int64InSlice(*host.BizGroupID, params.Groups) {
			return nil
		}
	}

	filtered := make([]DatabaseRecord, 0, len(rows))
	for _, row := range rows {
		if !matchRow(row, params) {
			continue
		}
		filtered = append(filtered, row)
	}
	return filtered
}

func matchRow(row DatabaseRecord, params DatabaseScanParams) bool {
	if params.Name != nil {
		if row.Name == nil || !filterutil.ContainsFold(*row.Name, *params.Name) {
			return false
		}
	}
	if len(params.Versions) > 0 {
		if row.Version == nil || !stringInSliceFold(*row.Version, params.Versions) {
			return false
		}
	}
	if params.Port != nil {
		if row.Port == nil || *row.Port != *params.Port {
			return false
		}
	}
	if params.ConfPath != nil {
		if row.ConfPath == nil || !filterutil.ContainsFold(*row.ConfPath, *params.ConfPath) {
			return false
		}
	}
	if params.LogPath != nil {
		if row.LogPath == nil || !filterutil.ContainsFold(*row.LogPath, *params.LogPath) {
			return false
		}
	}
	if params.DataDir != nil {
		if row.DataDir == nil || !filterutil.ContainsFold(*row.DataDir, *params.DataDir) {
			return false
		}
	}
	return true
}
