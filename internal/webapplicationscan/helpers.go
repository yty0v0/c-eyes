package webapplicationscan

import (
	"strings"

	"edrsystem/internal/filterutil"
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

func stringContainsAnyFold(value string, needles []string) bool {
	return filterutil.ContainsAnyFold(value, needles)
}
