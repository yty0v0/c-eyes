package websitescan

import (
	"strconv"
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

func stringInSliceFold(val string, list []string) bool {
	target := strings.TrimSpace(val)
	for _, item := range list {
		if strings.EqualFold(target, strings.TrimSpace(item)) {
			return true
		}
	}
	return false
}

func nullableString(v string) *string {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return nil
	}
	return strPtr(trimmed)
}

func stringOrEmpty(v *string) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(*v)
}

func toProtoFromPort(port int) string {
	switch port {
	case 443, 8443, 9443, 4433:
		return "https"
	default:
		return "http"
	}
}

func parsePort(value string) *int {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	n, err := strconv.Atoi(trimmed)
	if err != nil || n <= 0 {
		return nil
	}
	return intPtr(n)
}
