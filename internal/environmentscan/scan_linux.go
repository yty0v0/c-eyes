//go:build linux

package environmentscan

import (
	"bufio"
	"context"
	"os"
	"os/user"
	"strings"
)

func collectEnvironmentEntries(ctx context.Context) ([]EnvironmentInfo, error) {
	rows := make([]EnvironmentInfo, 0)
	seen := make(map[string]struct{})

	appendRow := func(key, value, userName string, sysEnv bool) {
		key = strings.TrimSpace(key)
		if key == "" {
			return
		}
		value = normalizeEnvValue(value)
		userName = strings.TrimSpace(userName)
		dedupeKey := strings.ToLower(key) + "\x00" + value + "\x00" + strings.ToLower(userName) + "\x00" + strings.ToLower(strconvBool(sysEnv))
		if _, ok := seen[dedupeKey]; ok {
			return
		}
		seen[dedupeKey] = struct{}{}
		rows = append(rows, EnvironmentInfo{
			Key:    strPtr(key),
			Value:  strPtr(value),
			User:   nullableString(userName),
			SysEnv: boolPtr(sysEnv),
		})
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, item := range parseSystemEnvironmentFile("/etc/environment") {
		appendRow(item.key, item.value, "root", true)
	}

	currentUser := currentUsername()
	for _, entry := range os.Environ() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		appendRow(key, value, currentUser, false)
	}

	return rows, nil
}

type envKV struct {
	key   string
	value string
}

func parseSystemEnvironmentFile(path string) []envKV {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	rows := make([]envKV, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		rows = append(rows, envKV{key: key, value: value})
	}
	return rows
}

func currentUsername() string {
	if u, err := user.Current(); err == nil && strings.TrimSpace(u.Username) != "" {
		return strings.TrimSpace(u.Username)
	}
	if val := strings.TrimSpace(os.Getenv("USER")); val != "" {
		return val
	}
	if val := strings.TrimSpace(os.Getenv("LOGNAME")); val != "" {
		return val
	}
	return ""
}

func strconvBool(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
