package processscan

import (
	"net"
	"sort"
)

func mergeProcessExternalIP(target map[int][]string, pid int, ip string) {
	if pid <= 0 || ip == "" {
		return
	}
	current := target[pid]
	for _, item := range current {
		if item == ip {
			return
		}
	}
	target[pid] = append(current, ip)
}

func normalizeProcessExternalIPMap(target map[int][]string) {
	for pid, ips := range target {
		if len(ips) == 0 {
			delete(target, pid)
			continue
		}
		sort.Strings(ips)
		target[pid] = ips
	}
}

func isExternalRemoteIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.IsPrivate() {
		return false
	}
	if v4 := ip.To4(); v4 != nil && isPrivateIP(v4) {
		return false
	}
	return true
}
