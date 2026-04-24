package accountscan

import (
	"time"

	"edrsystem/internal/filterutil"
	"edrsystem/internal/processscan"
)

// ApplyFilters filters account records with requested parameters.
func ApplyFilters(accounts []AccountInfo, params AccountScanParams, host processscan.HostInfo) []AccountInfo {
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

	filtered := make([]AccountInfo, 0, len(accounts))
	for _, account := range accounts {
		if !matchAccount(account, params) {
			continue
		}
		filtered = append(filtered, account)
	}
	return filtered
}

func matchAccount(account AccountInfo, params AccountScanParams) bool {
	if len(params.Status) > 0 {
		if account.Status == nil || !intInSlice(*account.Status, params.Status) {
			return false
		}
	}
	if params.Name != nil {
		if account.Name == nil || !filterutil.ContainsFold(*account.Name, *params.Name) {
			return false
		}
	}
	if params.Home != nil {
		if account.Home == nil || !filterutil.ContainsFold(*account.Home, *params.Home) {
			return false
		}
	}
	if params.GID != nil {
		if account.GID == nil || *account.GID != *params.GID {
			return false
		}
	}
	if params.UID != nil {
		if account.UID == nil || *account.UID != *params.UID {
			return false
		}
	}
	if params.LastLoginTime != nil {
		if !inDateRange(account.LastLoginTime, *params.LastLoginTime) {
			return false
		}
	}
	return true
}

func inDateRange(value *time.Time, dr DateRange) bool {
	if dr.From == nil && dr.To == nil {
		return true
	}
	if value == nil {
		return false
	}
	if dr.From != nil && value.Before(*dr.From) {
		return false
	}
	if dr.To != nil && value.After(*dr.To) {
		return false
	}
	return true
}

func intInSlice(val int, list []int) bool {
	for _, item := range list {
		if item == val {
			return true
		}
	}
	return false
}

func int64InSlice(val int64, list []int64) bool {
	for _, item := range list {
		if item == val {
			return true
		}
	}
	return false
}
