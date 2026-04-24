package webframescan

import (
	"strings"

	"edrsystem/internal/filterutil"
)

// applyFilters filters framework records with requested parameters.
func applyFilters(rows []WebFrameRecord, params WebFrameScanParams) []WebFrameRecord {
	filtered := make([]WebFrameRecord, 0, len(rows))
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

func matchHost(row WebFrameRecord, params WebFrameScanParams) bool {
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

func matchRow(row WebFrameRecord, params WebFrameScanParams) bool {
	if params.Name != nil {
		if row.Name == nil || !filterutil.ContainsFold(*row.Name, *params.Name) {
			return false
		}
	}
	if params.Version != nil {
		if row.Version == nil || !filterutil.ContainsFold(*row.Version, *params.Version) {
			return false
		}
	}
	if len(params.Type) > 0 {
		if row.Type == nil || !stringContainsAnyFold(*row.Type, params.Type) {
			return false
		}
	}
	if len(params.ServerName) > 0 {
		if row.ServerName == nil || !stringContainsAnyFold(*row.ServerName, params.ServerName) {
			return false
		}
	}
	return true
}

func matchIP(row WebFrameRecord, needle string) bool {
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
