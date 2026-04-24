package portscan

import (
	"net"
	"strings"
)

func int64InSlice(val int64, list []int64) bool {
	for _, item := range list {
		if item == val {
			return true
		}
	}
	return false
}

func normalizeMode(mode ScanMode) ScanMode {
	normalized := ScanMode(strings.TrimSpace(strings.ToLower(string(mode))))
	if normalized == "" {
		return ScanModeTCPConnect
	}
	switch normalized {
	case ScanModeTCPConnect, ScanModeTCPSYN:
		return normalized
	default:
		return ScanModeTCPConnect
	}
}

func normalizeProto(proto string) string {
	return strings.TrimSpace(strings.ToLower(proto))
}

func statusFromBindIP(bindIP string) *int {
	trimmed := strings.TrimSpace(bindIP)
	if trimmed == "" {
		return intPtr(-1)
	}
	if trimmed == "0.0.0.0" || trimmed == "::" || trimmed == "*" {
		return intPtr(1)
	}

	parsed := net.ParseIP(trimmed)
	if parsed == nil {
		return intPtr(-1)
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() {
		return intPtr(0)
	}
	return intPtr(1)
}
