package kernelscan

import (
	"context"

	"edrsystem/internal/processscan"
)

// KernelScanProvider defines a platform collector for kernel module scan.
type KernelScanProvider interface {
	Collect(ctx context.Context) ([]KernelModuleInfo, error)
}

var newKernelScanProvider = defaultKernelScanProvider

// Scan collects and filters kernel module information.
func Scan(ctx context.Context, params KernelScanParams) (KernelScanResult, error) {
	provider := newKernelScanProvider()
	rows, err := provider.Collect(ctx)
	if err != nil {
		return KernelScanResult{}, err
	}

	host, _ := processscan.GetHostInfo()
	total := len(rows)
	for i := range rows {
		applyHost(&rows[i], host)
		normalizeDefaults(&rows[i])
		if params.Progress != nil {
			params.Progress(i+1, total, "collect_kernel_modules")
		}
	}

	filtered := ApplyFilters(rows, params, host)
	if params.Progress != nil {
		params.Progress(total, total, "complete")
	}

	return KernelScanResult{
		Total: len(filtered),
		Rows:  filtered,
	}, nil
}

func applyHost(row *KernelModuleInfo, host processscan.HostInfo) {
	if host.DisplayIP != nil {
		row.DisplayIP = host.DisplayIP
	}
	if len(host.ExternalIPs) > 0 {
		row.ExternalIPs = append([]string(nil), host.ExternalIPs...)
	}
	if len(host.InternalIPs) > 0 {
		row.InternalIPs = append([]string(nil), host.InternalIPs...)
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

func normalizeDefaults(row *KernelModuleInfo) {
	if row.HostTagList == nil {
		row.HostTagList = []string{}
	}
	if row.ExternalIPs == nil {
		row.ExternalIPs = []string{}
	}
	if row.InternalIPs == nil {
		row.InternalIPs = []string{}
	}
	if row.Depends == nil {
		row.Depends = []string{}
	}
	if row.Holders == nil {
		row.Holders = []string{}
	}
}
