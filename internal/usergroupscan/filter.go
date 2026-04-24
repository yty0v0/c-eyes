package usergroupscan

import (
	"edrsystem/internal/filterutil"
	"edrsystem/internal/processscan"
)

// ApplyFilters filters user-group records with requested parameters.
func ApplyFilters(groups []UserGroupInfo, params UserGroupScanParams, host processscan.HostInfo) []UserGroupInfo {
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

	filtered := make([]UserGroupInfo, 0, len(groups))
	for _, group := range groups {
		if !matchGroup(group, params) {
			continue
		}
		filtered = append(filtered, group)
	}
	return filtered
}

func matchGroup(group UserGroupInfo, params UserGroupScanParams) bool {
	if params.Name != nil {
		if group.Name == nil || !filterutil.ContainsFold(*group.Name, *params.Name) {
			return false
		}
	}
	if params.GID != nil {
		if group.GID == nil || *group.GID != *params.GID {
			return false
		}
	}
	return true
}

func int64InSlice(val int64, list []int64) bool {
	for _, item := range list {
		if item == val {
			return true
		}
	}
	return false
}
