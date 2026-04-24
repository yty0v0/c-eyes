package jarpackagescan

import (
	"strings"

	"edrsystem/internal/filterutil"
)

// applyFilters filters jar package records with requested parameters.
func applyFilters(rows []JarPackageRecord, params JarPackageScanParams) []JarPackageRecord {
	filtered := make([]JarPackageRecord, 0, len(rows))
	for _, row := range rows {
		if !matchHost(row, params) {
			continue
		}
		if !matchRow(row, params) {
			continue
		}
		filtered = append(filtered, row)
	}
	return filtered
}

func matchHost(row JarPackageRecord, params JarPackageScanParams) bool {
	if params.Hostname != nil {
		if !filterutil.ContainsFold(stringOrEmpty(row.Hostname), *params.Hostname) {
			return false
		}
	}
	if params.IP != nil && !matchIP(row, *params.IP) {
		return false
	}
	if len(params.Groups) > 0 {
		if row.BizGroupID == nil || !int64InSlice(*row.BizGroupID, params.Groups) {
			return false
		}
	}
	return true
}

func matchRow(row JarPackageRecord, params JarPackageScanParams) bool {
	if params.Name != nil {
		if row.Name == nil || !filterutil.ContainsFold(*row.Name, *params.Name) {
			return false
		}
	}
	if len(params.Version) > 0 {
		if row.Version == nil || !stringContainsAnyFold(*row.Version, params.Version) {
			return false
		}
	}
	if len(params.Type) > 0 {
		if row.Type == nil || !intInSlice(*row.Type, params.Type) {
			return false
		}
	}
	if len(params.Executable) > 0 {
		if row.Executable == nil || !boolInSlice(*row.Executable, params.Executable) {
			return false
		}
	}
	if params.Path != nil {
		if row.Path == nil || !filterutil.ContainsFold(*row.Path, *params.Path) {
			return false
		}
	}
	return true
}

func matchIP(row JarPackageRecord, needle string) bool {
	lowerNeedle := strings.ToLower(needle)
	if row.DisplayIP != nil && filterutil.ContainsFoldLower(*row.DisplayIP, lowerNeedle) {
		return true
	}
	for _, ip := range row.InternalIPList {
		if filterutil.ContainsFoldLower(ip, lowerNeedle) {
			return true
		}
	}
	for _, ip := range row.ExternalIPList {
		if filterutil.ContainsFoldLower(ip, lowerNeedle) {
			return true
		}
	}
	return false
}
