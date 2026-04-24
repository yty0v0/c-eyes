package scheduledtaskscan

import "strings"

var supportedTaskTypes = map[string]struct{}{
	"CRONTAB": {},
	"AT":      {},
	"BATCH":   {},
}

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

func normalizeTaskType(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

func isValidTaskType(value string) bool {
	_, ok := supportedTaskTypes[normalizeTaskType(value)]
	return ok
}

// IsSupportedTaskType reports whether task type is in CRONTAB|AT|BATCH.
func IsSupportedTaskType(value string) bool {
	return isValidTaskType(value)
}

func nullableString(v string) *string {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return nil
	}
	return strPtr(trimmed)
}
