package filterutil

import (
	"strings"

	"edrsystem/internal/processscan"
)

// ContainsFold reports whether haystack contains needle, case-insensitively.
func ContainsFold(haystack, needle string) bool {
	return ContainsFoldLower(haystack, strings.ToLower(needle))
}

// ContainsFoldLower is like ContainsFold but accepts a pre-lowered needle.
func ContainsFoldLower(haystack, loweredNeedle string) bool {
	return strings.Contains(strings.ToLower(haystack), loweredNeedle)
}

// ContainsAnyFold reports whether haystack contains any needle, case-insensitively.
// It lower-cases haystack once to avoid repeated allocations in multi-needle checks.
func ContainsAnyFold(haystack string, needles []string) bool {
	if len(needles) == 0 {
		return false
	}
	lowerHaystack := strings.ToLower(haystack)
	for _, needle := range needles {
		if strings.Contains(lowerHaystack, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

// HostInfoContainsIP reports whether any host IP field contains needle, case-insensitively.
func HostInfoContainsIP(host processscan.HostInfo, needle string) bool {
	lowerNeedle := strings.ToLower(needle)
	if host.DisplayIP != nil && ContainsFoldLower(*host.DisplayIP, lowerNeedle) {
		return true
	}
	for _, ip := range host.InternalIPs {
		if ContainsFoldLower(ip, lowerNeedle) {
			return true
		}
	}
	for _, ip := range host.ExternalIPs {
		if ContainsFoldLower(ip, lowerNeedle) {
			return true
		}
	}
	for _, ip := range host.IPs {
		if ContainsFoldLower(ip, lowerNeedle) {
			return true
		}
	}
	return false
}
