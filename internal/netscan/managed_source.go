package netscan

import (
	"fmt"
	"strings"

	"edrsystem/internal/riskanalysis"
)

type managedMatcher struct {
	pairSet map[string]struct{}
	ipSet   map[string]struct{}
}

func loadManagedMatcher(path string) (*managedMatcher, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}

	records, err := riskanalysis.LoadScanRecords(path)
	if err != nil {
		return nil, fmt.Errorf("invalid argument: managedSource: %w", err)
	}

	matcher := &managedMatcher{
		pairSet: make(map[string]struct{}, len(records)),
		ipSet:   make(map[string]struct{}, len(records)),
	}

	for _, record := range records {
		flat := flattenStringMap(record.Raw, "")
		ip := extractByAliases(flat,
			"ipaddress", "ip", "ip_address", "displayip", "display_ip", "localip", "local_ip")
		mac := extractByAliases(flat,
			"macaddress", "mac", "mac_address")

		normalizedIP, hasIP := normalizeIP(ip)
		normalizedMAC, hasMAC := normalizeMAC(mac)
		if hasIP {
			matcher.ipSet[normalizedIP] = struct{}{}
		}
		if hasIP && hasMAC {
			matcher.pairSet[normalizedIP+"|"+normalizedMAC] = struct{}{}
		}
	}
	return matcher, nil
}

func (m *managedMatcher) classify(ip, mac string) string {
	if m == nil {
		return "unmanaged"
	}

	normalizedIP, hasIP := normalizeIP(ip)
	normalizedMAC, hasMAC := normalizeMAC(mac)
	if hasIP && hasMAC {
		if _, ok := m.pairSet[normalizedIP+"|"+normalizedMAC]; ok {
			return "managed"
		}
	}
	if hasIP {
		if _, ok := m.ipSet[normalizedIP]; ok {
			return "managed"
		}
	}
	return "unmanaged"
}

func flattenStringMap(input map[string]any, prefix string) map[string]string {
	out := map[string]string{}
	var walk func(path string, value any)
	walk = func(path string, value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, nested := range typed {
				next := strings.ToLower(strings.TrimSpace(key))
				if next == "" {
					continue
				}
				if path != "" {
					next = path + "." + next
				}
				walk(next, nested)
			}
		case []any:
			for _, item := range typed {
				walk(path, item)
			}
		default:
			if path == "" {
				return
			}
			value := strings.TrimSpace(fmt.Sprint(typed))
			if value == "" {
				return
			}
			out[path] = value
			last := path
			if idx := strings.LastIndex(path, "."); idx >= 0 && idx+1 < len(path) {
				last = path[idx+1:]
			}
			if _, exists := out[last]; !exists {
				out[last] = value
			}
		}
	}
	walk(strings.ToLower(strings.TrimSpace(prefix)), input)
	return out
}

func extractByAliases(flat map[string]string, aliases ...string) string {
	for _, alias := range aliases {
		key := strings.ToLower(strings.TrimSpace(alias))
		if key == "" {
			continue
		}
		if value, ok := flat[key]; ok && strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
