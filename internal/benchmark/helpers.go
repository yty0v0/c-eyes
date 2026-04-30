package benchmark

import "strings"

func normalizeLowerTrim(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
