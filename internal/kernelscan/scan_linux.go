//go:build linux

package kernelscan

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type linuxKernelScanProvider struct{}

func defaultKernelScanProvider() KernelScanProvider {
	return linuxKernelScanProvider{}
}

func (linuxKernelScanProvider) Collect(ctx context.Context) ([]KernelModuleInfo, error) {
	return collectLinuxKernelModules(ctx)
}

func collectLinuxKernelModules(ctx context.Context) ([]KernelModuleInfo, error) {
	file, err := os.Open("/proc/modules")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	paths := readLinuxModulePaths()
	rows := make([]KernelModuleInfo, 0, 256)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		row, ok := parseProcModulesLine(line)
		if !ok {
			continue
		}
		if p, ok := paths[strings.ToLower(*row.ModuleName)]; ok {
			row.Path = strPtr(p)
		}
		row.Holders = readLinuxModuleHolders(*row.ModuleName)
		if version := readLinuxModuleVersion(*row.ModuleName); version != "" {
			row.Version = strPtr(version)
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	sort.Slice(rows, func(i, j int) bool {
		li := ""
		if rows[i].ModuleName != nil {
			li = strings.ToLower(*rows[i].ModuleName)
		}
		lj := ""
		if rows[j].ModuleName != nil {
			lj = strings.ToLower(*rows[j].ModuleName)
		}
		return li < lj
	})

	return rows, nil
}

func parseProcModulesLine(line string) (KernelModuleInfo, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return KernelModuleInfo{}, false
	}
	name := strings.TrimSpace(fields[0])
	size := strings.TrimSpace(fields[1])
	if name == "" {
		return KernelModuleInfo{}, false
	}

	depends := parseLinuxDepends(fields[3])
	return KernelModuleInfo{
		ModuleName: nullableString(name),
		Size:       nullableString(size),
		Depends:    depends,
		Holders:    []string{},
	}, true
}

func parseLinuxDepends(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "-" {
		return []string{}
	}
	parts := strings.Split(trimmed, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		val := strings.TrimSpace(part)
		if val == "" {
			continue
		}
		out = append(out, val)
	}
	return out
}

func readLinuxModuleHolders(moduleName string) []string {
	dir := filepath.Join("/sys/module", moduleName, "holders")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{}
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := strings.TrimSpace(entry.Name())
		if name == "" {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func readLinuxModuleVersion(moduleName string) string {
	data, err := os.ReadFile(filepath.Join("/sys/module", moduleName, "version"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readLinuxModulePaths() map[string]string {
	release := linuxKernelRelease()
	if release == "" {
		return map[string]string{}
	}

	roots := []string{
		filepath.Join("/lib/modules", release),
		filepath.Join("/usr/lib/modules", release),
	}

	for _, root := range roots {
		depPath := filepath.Join(root, "modules.dep")
		mapping := parseLinuxModulesDep(depPath, root)
		if len(mapping) > 0 {
			return mapping
		}
	}
	return map[string]string{}
}

func linuxKernelRelease() string {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return ""
	}
	return charsToString(uname.Release[:])
}

func charsToString(raw []byte) string {
	n := 0
	for n < len(raw) && raw[n] != 0 {
		n++
	}
	return strings.TrimSpace(string(raw[:n]))
}

func parseLinuxModulesDep(path string, root string) map[string]string {
	file, err := os.Open(path)
	if err != nil {
		return map[string]string{}
	}
	defer file.Close()

	out := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		modulePath, ok := strings.CutSuffix(line, ":")
		if !ok {
			idx := strings.Index(line, ":")
			if idx < 0 {
				continue
			}
			modulePath = line[:idx]
		}
		modulePath = strings.TrimSpace(modulePath)
		if modulePath == "" {
			continue
		}
		key := linuxModuleKeyFromPath(modulePath)
		if key == "" {
			continue
		}
		finalPath := modulePath
		if !filepath.IsAbs(finalPath) {
			finalPath = filepath.Join(root, modulePath)
		}
		out[key] = filepath.Clean(finalPath)
	}
	return out
}

func linuxModuleKeyFromPath(path string) string {
	base := strings.ToLower(strings.TrimSpace(filepath.Base(path)))
	if base == "" {
		return ""
	}
	suffixes := []string{
		".ko.zst",
		".ko.xz",
		".ko.gz",
		".ko.bz2",
		".ko",
	}
	for _, suffix := range suffixes {
		if strings.HasSuffix(base, suffix) {
			base = strings.TrimSuffix(base, suffix)
			break
		}
	}
	return strings.TrimSpace(base)
}
