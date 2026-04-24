//go:build !windows

package filescan

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
)

// PersistenceCollector gathers autostart/persistence targets on Unix-like systems.
type PersistenceCollector struct{}

func (PersistenceCollector) Collect(ctx context.Context, params FileScanParams) ([]ScanTask, error) {
	_ = ctx
	var roots []string
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots, filepath.Join(home, ".config", "autostart"))
	}
	roots = append(roots, "/etc/xdg/autostart")

	var candidates []string
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".desktop") {
				continue
			}
			path := filepath.Join(root, entry.Name())
			if exec := readDesktopExec(path); exec != "" {
				candidates = append(candidates, exec)
			}
		}
	}

	tasks := make([]ScanTask, 0, len(candidates))
	for _, path := range candidates {
		if path == "" {
			continue
		}
		tasks = append(tasks, ScanTask{
			Path:   path,
			Source: SourcePersistence,
			Mode:   ScanModeSmart,
		})
	}
	return dedupeTasks(tasks), nil
}

func readDesktopExec(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(strings.ToLower(line), "exec=") {
			continue
		}
		cmd := strings.TrimSpace(line[5:])
		return extractDesktopCommand(cmd)
	}
	return ""
}

func extractDesktopCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	if strings.HasPrefix(cmd, "\"") {
		rest := cmd[1:]
		if idx := strings.Index(rest, "\""); idx >= 0 {
			return rest[:idx]
		}
	}
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
