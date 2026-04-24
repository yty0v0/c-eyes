//go:build windows

package environmentscan

import (
	"context"
	"os"
	"os/user"
	"strings"

	"golang.org/x/sys/windows/registry"
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

	appendRegistryEnvironment(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, "SYSTEM", true, appendRow)
	currentUser := currentUsername()
	appendRegistryEnvironment(registry.CURRENT_USER, `Environment`, currentUser, false, appendRow)

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

func appendRegistryEnvironment(
	root registry.Key,
	path string,
	userName string,
	sysEnv bool,
	appendRow func(key, value, userName string, sysEnv bool),
) {
	key, err := registry.OpenKey(root, path, registry.READ)
	if err != nil {
		return
	}
	defer key.Close()

	names, err := key.ReadValueNames(-1)
	if err != nil {
		return
	}
	for _, name := range names {
		if strings.TrimSpace(name) == "" {
			continue
		}
		if value, _, err := key.GetStringValue(name); err == nil {
			appendRow(name, value, userName, sysEnv)
		}
	}
}

func currentUsername() string {
	if u, err := user.Current(); err == nil && strings.TrimSpace(u.Username) != "" {
		return strings.TrimSpace(u.Username)
	}
	if val := strings.TrimSpace(os.Getenv("USERNAME")); val != "" {
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
