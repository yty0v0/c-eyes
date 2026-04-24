//go:build windows

package filescan

import (
	"bufio"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// PersistenceCollector gathers autostart/persistence targets on Windows.
type PersistenceCollector struct{}

func (PersistenceCollector) Collect(ctx context.Context, params FileScanParams) ([]ScanTask, error) {
	_ = ctx
	var candidates []string

	runKeys := []struct {
		root registry.Key
		path string
	}{
		{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`},
		{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
		{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`},
		{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
	}
	for _, item := range runKeys {
		values, _ := readRunKey(item.root, item.path)
		candidates = append(candidates, values...)
	}

	candidates = append(candidates, collectServiceImagePaths()...)
	candidates = append(candidates, collectStartupFolderFiles()...)
	candidates = append(candidates, collectScheduledTaskCommands()...)

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

func readRunKey(root registry.Key, path string) ([]string, error) {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return nil, nil
	}
	defer key.Close()

	names, err := key.ReadValueNames(0)
	if err != nil {
		return nil, nil
	}
	var out []string
	for _, name := range names {
		value, _, err := key.GetStringValue(name)
		if err != nil {
			continue
		}
		if path := extractCommandPath(value); path != "" {
			out = append(out, path)
		}
	}
	return out, nil
}

func collectServiceImagePaths() []string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer key.Close()

	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}
	var out []string
	for _, name := range names {
		sub, err := registry.OpenKey(key, name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		value, _, err := sub.GetStringValue("ImagePath")
		sub.Close()
		if err != nil {
			continue
		}
		if path := extractCommandPath(value); path != "" {
			out = append(out, path)
		}
	}
	return out
}

func collectStartupFolderFiles() []string {
	var roots []string
	if appData := os.Getenv("APPDATA"); appData != "" {
		roots = append(roots, filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
	}
	if programData := os.Getenv("ProgramData"); programData != "" {
		roots = append(roots, filepath.Join(programData, "Microsoft", "Windows", "Start Menu", "Programs", "StartUp"))
	}
	var out []string
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			out = append(out, filepath.Join(root, entry.Name()))
		}
	}
	return out
}

func collectScheduledTaskCommands() []string {
	root := filepath.Join(os.Getenv("SystemRoot"), "System32", "Tasks")
	if root == "" {
		return nil
	}
	var out []string
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if !strings.Contains(line, "<Command>") {
				continue
			}
			start := strings.Index(line, "<Command>")
			end := strings.Index(line, "</Command>")
			if start >= 0 && end > start {
				cmd := line[start+len("<Command>") : end]
				if path := extractCommandPath(cmd); path != "" {
					out = append(out, path)
				}
				break
			}
		}
		return nil
	})
	return out
}

var envPattern = regexp.MustCompile(`%[^%]+%`)

func expandEnvWindows(input string) string {
	return envPattern.ReplaceAllStringFunc(input, func(token string) string {
		key := strings.Trim(token, "%")
		if key == "" {
			return token
		}
		if val := os.Getenv(key); val != "" {
			return val
		}
		return token
	})
}

func extractCommandPath(cmd string) string {
	trimmed := strings.TrimSpace(cmd)
	if trimmed == "" {
		return ""
	}
	trimmed = expandEnvWindows(trimmed)
	if strings.HasPrefix(trimmed, `\\SystemRoot\\`) {
		if root := os.Getenv("SystemRoot"); root != "" {
			trimmed = filepath.Join(root, strings.TrimPrefix(trimmed, `\\SystemRoot\\`))
		}
	}
	if strings.HasPrefix(trimmed, "\"") {
		rest := trimmed[1:]
		if idx := strings.Index(rest, "\""); idx >= 0 {
			return filepath.Clean(rest[:idx])
		}
	}
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return ""
	}
	return filepath.Clean(strings.Trim(fields[0], `"`))
}
