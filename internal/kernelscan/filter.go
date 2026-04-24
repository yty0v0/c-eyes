package kernelscan

import (
	"edrsystem/internal/filterutil"
	"edrsystem/internal/processscan"
)

// ApplyFilters filters kernel module records with requested parameters.
func ApplyFilters(rows []KernelModuleInfo, params KernelScanParams, host processscan.HostInfo) []KernelModuleInfo {
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

	filtered := make([]KernelModuleInfo, 0, len(rows))
	for _, row := range rows {
		if !matchRow(row, params) {
			continue
		}
		filtered = append(filtered, row)
	}
	return filtered
}

func matchRow(row KernelModuleInfo, params KernelScanParams) bool {
	if params.ModuleName != nil {
		if row.ModuleName == nil || !filterutil.ContainsFold(*row.ModuleName, *params.ModuleName) {
			return false
		}
	}
	if params.Path != nil {
		if row.Path == nil || !filterutil.ContainsFold(*row.Path, *params.Path) {
			return false
		}
	}
	if len(params.Version) > 0 {
		if row.Version == nil || !stringInSliceFold(*row.Version, params.Version) {
			return false
		}
	}
	return true
}
