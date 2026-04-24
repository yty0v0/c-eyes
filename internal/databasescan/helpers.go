package databasescan

import "strings"

func int64InSlice(val int64, list []int64) bool {
	for _, item := range list {
		if item == val {
			return true
		}
	}
	return false
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

func pickFirst(items ...string) *string {
	for _, item := range items {
		if out := nullableString(item); out != nil {
			return out
		}
	}
	return nil
}

func normalizeDBName(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func extractArgValue(args []string, keys ...string) string {
	for i := 0; i < len(args); i++ {
		item := strings.TrimSpace(args[i])
		for _, key := range keys {
			if item == key && i+1 < len(args) {
				return strings.Trim(strings.TrimSpace(args[i+1]), `"`)
			}
			prefix := key + "="
			if strings.HasPrefix(item, prefix) {
				return strings.Trim(strings.TrimSpace(strings.TrimPrefix(item, prefix)), `"`)
			}
		}
	}
	return ""
}

func hasArg(args []string, key string) bool {
	for _, item := range args {
		if strings.EqualFold(strings.TrimSpace(item), key) {
			return true
		}
	}
	return false
}
