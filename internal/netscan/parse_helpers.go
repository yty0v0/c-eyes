package netscan

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseModesCSV parses scan mode input from CLI.
func ParseModesCSV(raw string) ([]ScanMode, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	parts := splitCSV(trimmed)
	if len(parts) == 0 {
		return nil, nil
	}

	out := make([]ScanMode, 0, len(parts))
	seen := map[ScanMode]struct{}{}
	for _, part := range parts {
		mode := ScanMode(strings.ToUpper(strings.TrimSpace(part)))
		if _, ok := modeCapabilities[mode]; !ok {
			return nil, fmt.Errorf("invalid argument: scanMode contains unsupported mode: %s", part)
		}
		if _, ok := seen[mode]; ok {
			continue
		}
		seen[mode] = struct{}{}
		out = append(out, mode)
	}
	return out, nil
}

// ParsePortsCSV parses comma-separated port numbers.
func ParsePortsCSV(raw string, fieldName string) ([]int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := splitCSV(raw)
	ports := make([]int, 0, len(parts))
	for _, item := range parts {
		value, err := strconv.Atoi(strings.TrimSpace(item))
		if err != nil {
			return nil, fmt.Errorf("invalid argument: %s contains invalid port: %s", fieldName, item)
		}
		if value < 1 || value > 65535 {
			return nil, fmt.Errorf("invalid argument: %s only supports ports between 1 and 65535", fieldName)
		}
		ports = append(ports, value)
	}
	return normalizePorts(ports), nil
}

func splitCSV(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}
