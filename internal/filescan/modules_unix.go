//go:build !windows

package filescan

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func collectProcessModules(pid int) ([]string, error) {
	if pid <= 0 {
		return nil, nil
	}
	path := filepath.Join("/proc", strconv.Itoa(pid), "maps")
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	paths := make([]string, 0, 16)
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		pathname := fields[len(fields)-1]
		if !strings.HasPrefix(pathname, "/") {
			continue
		}
		if !isModulePath(pathname) {
			continue
		}
		if _, ok := seen[pathname]; ok {
			continue
		}
		seen[pathname] = struct{}{}
		paths = append(paths, pathname)
	}
	if err := scanner.Err(); err != nil {
		return paths, err
	}
	return paths, nil
}

func isModulePath(path string) bool {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".so") || strings.Contains(lower, ".so.") {
		return true
	}
	if strings.HasSuffix(lower, ".dylib") {
		return true
	}
	return false
}
