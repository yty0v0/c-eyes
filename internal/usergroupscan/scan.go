package usergroupscan

import (
	"context"

	"edrsystem/internal/processscan"
)

var collectUserGroupsFn = collectUserGroups

// Scan collects and filters host user-group information.
func Scan(ctx context.Context, params UserGroupScanParams) (UserGroupScanResult, error) {
	groups, err := collectUserGroupsFn(ctx)
	if err != nil {
		return UserGroupScanResult{}, err
	}

	host, _ := processscan.GetHostInfo()
	total := len(groups)
	for i := range groups {
		applyHost(&groups[i], host)
		normalizeDefaults(&groups[i])
		if params.Progress != nil {
			params.Progress(i+1, total, "collect_user_groups")
		}
	}

	filtered := ApplyFilters(groups, params, host)
	if params.Progress != nil {
		params.Progress(total, total, "complete")
	}

	return UserGroupScanResult{
		Total: len(filtered),
		Rows:  filtered,
	}, nil
}

func applyHost(group *UserGroupInfo, host processscan.HostInfo) {
	if host.DisplayIP != nil {
		group.DisplayIP = host.DisplayIP
	}
	if len(host.ExternalIPs) > 0 {
		group.ExternalIPList = append([]string(nil), host.ExternalIPs...)
	}
	if len(host.InternalIPs) > 0 {
		group.InternalIPList = append([]string(nil), host.InternalIPs...)
	}
	if host.BizGroupID != nil {
		group.BizGroupID = host.BizGroupID
	}
	if host.BizGroup != nil {
		group.BizGroup = host.BizGroup
	}
	if host.Remark != nil {
		group.Remark = host.Remark
	}
	if len(host.HostTagList) > 0 {
		group.HostTagList = append([]string(nil), host.HostTagList...)
	}
	if host.Hostname != "" {
		group.Hostname = strPtr(host.Hostname)
	}
}

func normalizeDefaults(group *UserGroupInfo) {
	if group.HostTagList == nil {
		group.HostTagList = []string{}
	}
	if group.ExternalIPList == nil {
		group.ExternalIPList = []string{}
	}
	if group.InternalIPList == nil {
		group.InternalIPList = []string{}
	}
	if group.Members == nil {
		group.Members = []GroupMember{}
	}
}
