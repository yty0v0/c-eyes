package processscan

import "context"

// Scan performs a process scan and returns normalized results.
func Scan(ctx context.Context, params ProcessScanParams) ([]ProcessInfo, error) {
	_ = ctx

	host, _ := GetHostInfo()
	processes, err := scanProcesses()
	if err != nil {
		return nil, err
	}
	processExternalIPs, err := collectProcessExternalIPs(ctx)
	if err != nil {
		processExternalIPs = map[int][]string{}
	}

	total := len(processes)
	for i := range processes {
		if processes[i].PID != nil {
			if ips, ok := processExternalIPs[*processes[i].PID]; ok {
				processes[i].ProcessExternalIPList = append([]string(nil), ips...)
			}
		}
		applyHost(&processes[i], host)
		if params.Progress != nil {
			params.Progress(i+1, total, "collect_processes")
		}
	}

	filtered := ApplyFilters(processes, params, host)
	if params.Progress != nil {
		params.Progress(total, total, "complete")
	}
	return filtered, nil
}

func applyHost(proc *ProcessInfo, host HostInfo) {
	if host.DisplayIP != nil {
		proc.DisplayIP = host.DisplayIP
	}
	if len(host.ExternalIPs) > 0 {
		proc.ExternalIPList = append([]string(nil), host.ExternalIPs...)
	}
	if len(host.InternalIPs) > 0 {
		proc.InternalIPList = append([]string(nil), host.InternalIPs...)
	}
	if proc.ExternalIPList == nil {
		proc.ExternalIPList = []string{}
	}
	if proc.InternalIPList == nil {
		proc.InternalIPList = []string{}
	}
	if proc.ProcessExternalIPList == nil {
		proc.ProcessExternalIPList = []string{}
	}
	if host.BizGroupID != nil {
		proc.BizGroupID = host.BizGroupID
	}
	if host.BizGroup != nil {
		proc.BizGroup = host.BizGroup
	}
	if host.Remark != nil {
		proc.Remark = host.Remark
	}
	if host.HostTagList != nil {
		proc.HostTagList = host.HostTagList
	}
	if host.Hostname != "" {
		proc.Hostname = strPtr(host.Hostname)
	}
}
