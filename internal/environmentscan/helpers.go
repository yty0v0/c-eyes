package environmentscan

import "strings"

func int64InSlice(val int64, list []int64) bool {
	for _, item := range list {
		if item == val {
			return true
		}
	}
	return false
}

func boolInSlice(val bool, list []bool) bool {
	for _, item := range list {
		if item == val {
			return true
		}
	}
	return false
}

func nullableString(v string) *string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return strPtr(strings.TrimSpace(v))
}

func normalizeEnvValue(v string) string {
	trimmed := strings.TrimSpace(v)
	trimmed = strings.Trim(trimmed, `"'`)
	return strings.TrimSpace(trimmed)
}
