package webapplicationscan

import (
	"context"
	"strings"

	"edrsystem/internal/processscan"
)

var collectWebApplicationsFn = collectWebApplications
var enableProcessAssociation = true

// Scan collects and filters web application information.
func Scan(ctx context.Context, params WebApplicationScanParams) (WebApplicationScanResult, error) {
	rows, err := collectWebApplicationsFn(ctx)
	if err != nil {
		return WebApplicationScanResult{}, err
	}
	if enableProcessAssociation {
		rows = enrichWebApplicationsWithProcesses(ctx, rows)
	}

	host, _ := processscan.GetHostInfo()
	total := len(rows)
	for i := range rows {
		applyHost(&rows[i], host)
		normalizeDefaults(&rows[i])
		if params.Progress != nil {
			params.Progress(i+1, total, "collect_web_application")
		}
	}

	filtered := ApplyFilters(rows, params, host)
	if params.Progress != nil {
		params.Progress(total, total, "complete")
	}

	return WebApplicationScanResult{
		Total: len(filtered),
		Rows:  filtered,
	}, nil
}

func applyHost(row *WebApplicationInfo, host processscan.HostInfo) {
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

func normalizeDefaults(row *WebApplicationInfo) {
	if row.HostTagList == nil {
		row.HostTagList = []string{}
	}
	if row.ExternalIPList == nil {
		row.ExternalIPList = []string{}
	}
	if row.InternalIPList == nil {
		row.InternalIPList = []string{}
	}
	if row.Plugins == nil {
		row.Plugins = []PluginInfo{}
	}

	for i := range row.Plugins {
		row.Plugins[i].PluginName = nullableString(stringOrEmpty(row.Plugins[i].PluginName))
		row.Plugins[i].PluginURI = nullableString(stringOrEmpty(row.Plugins[i].PluginURI))
		row.Plugins[i].Description = nullableString(stringOrEmpty(row.Plugins[i].Description))
		row.Plugins[i].Author = nullableString(stringOrEmpty(row.Plugins[i].Author))
		row.Plugins[i].AuthorURI = nullableString(stringOrEmpty(row.Plugins[i].AuthorURI))
		row.Plugins[i].Version = nullableString(stringOrEmpty(row.Plugins[i].Version))
	}

	row.AppName = nullableString(stringOrEmpty(row.AppName))
	row.ServerName = nullableString(stringOrEmpty(row.ServerName))
	row.Version = nullableString(stringOrEmpty(row.Version))
	row.WebRoot = nullableString(stringOrEmpty(row.WebRoot))
	row.RootPath = nullableString(stringOrEmpty(row.RootPath))
	row.DomainName = nullableString(stringOrEmpty(row.DomainName))
	row.Description = nullableString(stringOrEmpty(row.Description))

	if row.PluginCount == nil {
		row.PluginCount = intPtr(len(row.Plugins))
	}
	if row.IsRunning == nil {
		row.IsRunning = boolPtr(false)
	}
}

func stringOrEmpty(v *string) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(*v)
}
