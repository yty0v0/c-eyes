package websitescan

import (
	"context"
	"strings"

	"edrsystem/internal/processscan"
)

var collectWebSitesFn = collectWebSites
var enableWebSiteProcessAssociation = true

// Scan collects and filters web site information.
func Scan(ctx context.Context, params WebSiteScanParams) (WebSiteScanResult, error) {
	rows, err := collectWebSitesFn(ctx)
	if err != nil {
		return WebSiteScanResult{}, err
	}
	if enableWebSiteProcessAssociation {
		rows = enrichWebSitesWithProcesses(ctx, rows)
	}

	host, _ := processscan.GetHostInfo()
	total := len(rows)
	for i := range rows {
		applyHost(&rows[i], host)
		normalizeDefaults(&rows[i])
		if params.Progress != nil {
			params.Progress(i+1, total, "collect_web_site")
		}
	}

	filtered := ApplyFilters(rows, params, host)
	if params.Progress != nil {
		params.Progress(total, total, "complete")
	}

	return WebSiteScanResult{
		Total: len(filtered),
		Rows:  filtered,
	}, nil
}

func applyHost(row *WebSiteInfo, host processscan.HostInfo) {
	if host.DisplayIP != nil {
		row.DisplayIP = host.DisplayIP
	}
	if len(host.ExternalIPs) > 0 {
		row.ExternalIPList = append([]string(nil), host.ExternalIPs...)
	}
	if len(host.InternalIPs) > 0 {
		row.InternalIPList = append([]string(nil), host.InternalIPs...)
	}
	if host.BizGroupID != nil {
		row.BizGroupID = host.BizGroupID
	}
	if host.BizGroup != nil {
		row.BizGroup = host.BizGroup
	}
	if host.Remark != nil {
		row.Remark = host.Remark
	}
	if len(host.HostTagList) > 0 {
		row.HostTagList = append([]string(nil), host.HostTagList...)
	}
	if host.Hostname != "" {
		row.Hostname = strPtr(host.Hostname)
	}
}

func normalizeDefaults(row *WebSiteInfo) {
	if row.HostTagList == nil {
		row.HostTagList = []string{}
	}
	if row.ExternalIPList == nil {
		row.ExternalIPList = []string{}
	}
	if row.InternalIPList == nil {
		row.InternalIPList = []string{}
	}
	if row.Domains == nil {
		row.Domains = []DomainInfo{}
	}
	if row.VirtualDir == nil {
		row.VirtualDir = []VirtualDirInfo{}
	}

	if row.PortStatus == nil {
		row.PortStatus = intPtr(-1)
	}
	if row.SecurityEnabled == nil {
		row.SecurityEnabled = boolPtr(false)
	}

	for i := range row.Domains {
		row.Domains[i].Name = nullableString(stringOrEmpty(row.Domains[i].Name))
		row.Domains[i].Title = nullableString(stringOrEmpty(row.Domains[i].Title))
		row.Domains[i].IP = nullableString(stringOrEmpty(row.Domains[i].IP))
	}
	for i := range row.VirtualDir {
		vd := &row.VirtualDir[i]
		vd.Path = nullableString(stringOrEmpty(vd.Path))
		vd.PhysicalPath = nullableString(stringOrEmpty(vd.PhysicalPath))
		vd.Owner = nullableString(stringOrEmpty(vd.Owner))
		vd.Permission = nullableString(stringOrEmpty(vd.Permission))
		vd.AppPath = nullableString(stringOrEmpty(vd.AppPath))
		if vd.ACLs == nil {
			vd.ACLs = []ACLInfo{}
		}
	}
	if row.Root == nil {
		for i := range row.VirtualDir {
			if row.VirtualDir[i].Root != nil && *row.VirtualDir[i].Root {
				rootCopy := row.VirtualDir[i]
				row.Root = &rootCopy
				break
			}
		}
	}
	if row.VirtualDirCount == nil {
		row.VirtualDirCount = intPtr(len(row.VirtualDir))
	}
	if row.BindingCount == nil {
		row.BindingCount = intPtr(len(row.Domains))
	}

	row.Allow = nullableString(stringOrEmpty(row.Allow))
	row.Deny = nullableString(stringOrEmpty(row.Deny))
	row.Cmd = nullableString(stringOrEmpty(row.Cmd))
	row.User = nullableString(stringOrEmpty(row.User))
	row.Type = nullableString(stringOrEmpty(row.Type))
	row.Proto = nullableString(strings.ToLower(stringOrEmpty(row.Proto)))
	row.DeployPath = nullableString(stringOrEmpty(row.DeployPath))
	row.ConfigName = nullableString(stringOrEmpty(row.ConfigName))
	row.Path = nullableString(stringOrEmpty(row.Path))
	if row.IsRunning == nil {
		row.IsRunning = boolPtr(false)
	}
}
