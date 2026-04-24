package usergroupscan

import (
	"strconv"
	"strings"
)

type linuxGroupEntry struct {
	Name    string
	GID     int64
	Members []string
}

func parseGroupFile(data []byte) []linuxGroupEntry {
	lines := splitLines(string(data))
	out := make([]linuxGroupEntry, 0, len(lines))
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 4)
		if len(parts) < 4 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		if name == "" {
			continue
		}
		gid, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil {
			continue
		}

		out = append(out, linuxGroupEntry{
			Name:    name,
			GID:     gid,
			Members: dedupeMembers(parts[3]),
		})
	}
	return out
}

func dedupeMembers(raw string) []string {
	chunks := strings.Split(raw, ",")
	if len(chunks) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(chunks))
	out := make([]string, 0, len(chunks))
	for _, chunk := range chunks {
		member := strings.TrimSpace(chunk)
		if member == "" {
			continue
		}
		if _, ok := seen[member]; ok {
			continue
		}
		seen[member] = struct{}{}
		out = append(out, member)
	}
	return out
}

func splitLines(input string) []string {
	raw := strings.Split(input, "\n")
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}
