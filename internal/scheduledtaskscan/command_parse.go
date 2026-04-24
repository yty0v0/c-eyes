package scheduledtaskscan

import "strings"

func parseExecutableFromCommand(command string) string {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "\"") {
		rest := strings.TrimPrefix(trimmed, "\"")
		if idx := strings.Index(rest, "\""); idx >= 0 {
			return strings.TrimSpace(rest[:idx])
		}
	}
	parts := strings.Fields(trimmed)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}
