package processscan

import "strings"

// ApplyFilters returns a filtered list based on scan parameters.
func ApplyFilters(procs []ProcessInfo, params ProcessScanParams, host HostInfo) []ProcessInfo {
	hostnameNeedle := lowerNeedle(params.Hostname)
	ipNeedle := lowerNeedle(params.IP)
	packageNameNeedle := lowerNeedle(params.PackageName)
	stateNeedle := lowerNeedle(params.State)
	pathNeedle := lowerNeedle(params.Path)
	unameNeedle := lowerNeedle(params.Uname)
	gnameNeedle := lowerNeedle(params.Gname)
	nameNeedle := lowerNeedle(params.Name)
	startArgsNeedle := lowerNeedle(params.StartArgs)
	ttyNeedle := lowerNeedle(params.TTY)
	descriptionNeedle := lowerNeedle(params.Description)

	if params.Hostname != nil {
		if !containsFoldLower(host.Hostname, hostnameNeedle) {
			return nil
		}
	}
	if params.IP != nil {
		if !hostIPMatch(host, ipNeedle) {
			return nil
		}
	}

	if len(procs) == 0 {
		return procs
	}

	filtered := make([]ProcessInfo, 0, len(procs))
	for _, proc := range procs {
		if !matchProcess(
			proc,
			params,
			packageNameNeedle,
			stateNeedle,
			pathNeedle,
			unameNeedle,
			gnameNeedle,
			nameNeedle,
			startArgsNeedle,
			ttyNeedle,
			descriptionNeedle,
		) {
			continue
		}
		filtered = append(filtered, proc)
	}
	return filtered
}

func matchProcess(
	proc ProcessInfo,
	params ProcessScanParams,
	packageNameNeedle string,
	stateNeedle string,
	pathNeedle string,
	unameNeedle string,
	gnameNeedle string,
	nameNeedle string,
	startArgsNeedle string,
	ttyNeedle string,
	descriptionNeedle string,
) bool {
	if params.StartTime != nil {
		if proc.StartTime == nil || proc.StartTime.Before(*params.StartTime) {
			return false
		}
	}
	if params.Root != nil {
		if proc.Root == nil || *proc.Root != *params.Root {
			return false
		}
	}
	if params.InstalledByPm != nil {
		if proc.InstallByPm == nil || *proc.InstallByPm != *params.InstalledByPm {
			return false
		}
	}
	if len(params.PIDs) > 0 {
		if proc.PID == nil || !intInSlice(*proc.PID, params.PIDs) {
			return false
		}
	}
	if len(params.Types) > 0 {
		if proc.Type == nil || !intInSlice(*proc.Type, params.Types) {
			return false
		}
	}
	if len(params.Versions) > 0 {
		if proc.Version == nil || !stringInSliceFold(*proc.Version, params.Versions) {
			return false
		}
	}
	if len(params.PackageVersions) > 0 {
		if proc.PackageVersion == nil || !stringInSliceFold(*proc.PackageVersion, params.PackageVersions) {
			return false
		}
	}
	if params.PackageName != nil {
		if proc.PackageName == nil || !containsFoldLower(*proc.PackageName, packageNameNeedle) {
			return false
		}
	}
	if params.State != nil {
		if proc.State == nil || !containsFoldLower(*proc.State, stateNeedle) {
			return false
		}
	}
	if params.Path != nil {
		if proc.Path == nil || !containsFoldLower(*proc.Path, pathNeedle) {
			return false
		}
	}
	if params.Uname != nil {
		if proc.Uname == nil || !containsFoldLower(*proc.Uname, unameNeedle) {
			return false
		}
	}
	if params.Gname != nil {
		if proc.Gname == nil || !containsFoldLower(*proc.Gname, gnameNeedle) {
			return false
		}
	}
	if params.Name != nil {
		if proc.Name == nil || !containsFoldLower(*proc.Name, nameNeedle) {
			return false
		}
	}
	if params.StartArgs != nil {
		if proc.StartArgs == nil || !containsFoldLower(*proc.StartArgs, startArgsNeedle) {
			return false
		}
	}
	if params.TTY != nil {
		if proc.TTY == nil || !containsFoldLower(*proc.TTY, ttyNeedle) {
			return false
		}
	}
	if params.Description != nil {
		if proc.Description == nil || !containsFoldLower(*proc.Description, descriptionNeedle) {
			return false
		}
	}
	return true
}

func hostIPMatch(host HostInfo, loweredNeedle string) bool {
	if host.DisplayIP != nil && containsFoldLower(*host.DisplayIP, loweredNeedle) {
		return true
	}
	for _, ip := range host.InternalIPs {
		if containsFoldLower(ip, loweredNeedle) {
			return true
		}
	}
	for _, ip := range host.ExternalIPs {
		if containsFoldLower(ip, loweredNeedle) {
			return true
		}
	}
	for _, ip := range host.IPs {
		if containsFoldLower(ip, loweredNeedle) {
			return true
		}
	}
	return false
}

func containsFold(haystack, needle string) bool {
	return containsFoldLower(haystack, strings.ToLower(needle))
}

func containsFoldLower(haystack, loweredNeedle string) bool {
	return strings.Contains(strings.ToLower(haystack), loweredNeedle)
}

func lowerNeedle(value *string) string {
	if value == nil {
		return ""
	}
	return strings.ToLower(*value)
}

func intInSlice(val int, list []int) bool {
	for _, item := range list {
		if item == val {
			return true
		}
	}
	return false
}

func stringInSliceFold(val string, list []string) bool {
	for _, item := range list {
		if strings.EqualFold(item, val) {
			return true
		}
	}
	return false
}
