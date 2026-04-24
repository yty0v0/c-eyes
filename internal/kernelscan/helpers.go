package kernelscan

import "strings"

func int64InSlice(val int64, list []int64) bool {
	for _, item := range list {
		if item == val {
			return true
		}
	}
	return false
}

func stringInSliceFold(val string, list []string) bool {
	for _, item := range list {
		if strings.EqualFold(strings.TrimSpace(item), strings.TrimSpace(val)) {
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
