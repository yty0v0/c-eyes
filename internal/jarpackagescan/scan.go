package jarpackagescan

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"edrsystem/internal/processscan"
	"edrsystem/internal/webframescan"
)

var (
	scanWebFrameFn = webframescan.Scan
	scanProcessFn  = processscan.Scan
	jarVersionRe   = regexp.MustCompile(`([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
)

// Scan collects and filters jar package information.
func Scan(ctx context.Context, params JarPackageScanParams) (JarPackageScanResult, error) {
	webParams := webframescan.WebFrameScanParams{
		Groups:   append([]int64(nil), params.Groups...),
		Hostname: cloneStringPtr(params.Hostname),
		IP:       cloneStringPtr(params.IP),
	}

	webResult, err := scanWebFrameFn(ctx, webParams)
	if err != nil {
		return JarPackageScanResult{}, err
	}

	rows := collectFromWebFramework(webResult.Rows)

	if procRows, err := scanProcessFn(ctx, processscan.ProcessScanParams{}); err == nil {
		rows = append(rows, collectFromProcesses(procRows)...)
	}

	merged := mergeRows(rows)
	filtered := applyFilters(merged, params)

	if params.Progress != nil {
		params.Progress(len(filtered), len(filtered), "complete")
	}

	return JarPackageScanResult{
		Total: len(filtered),
		Rows:  filtered,
	}, nil
}

func collectFromWebFramework(rows []webframescan.WebFrameRecord) []JarPackageRecord {
	out := make([]JarPackageRecord, 0, len(rows))
	for _, row := range rows {
		if len(row.JarList) == 0 {
			continue
		}
		for _, jar := range row.JarList {
			path := buildJarPath(jar.AbsDir, jar.JarName)
			version := cloneStringPtr(jar.Version)
			if version == nil {
				version = nullableString(detectVersionFromJarName(stringOrEmpty(jar.JarName)))
			}

			record := JarPackageRecord{
				DisplayIP:      cloneStringPtr(row.DisplayIP),
				ExternalIPList: cloneStrings(row.ExternalIPList),
				InternalIPList: cloneStrings(row.InternalIPList),
				BizGroupID:     cloneInt64Ptr(row.BizGroupID),
				BizGroup:       cloneStringPtr(row.BizGroup),
				Remark:         cloneStringPtr(row.Remark),
				HostTagList:    cloneStrings(row.HostTagList),
				Hostname:       cloneStringPtr(row.Hostname),
				Name:           cloneStringPtr(jar.JarName),
				Version:        version,
				Type:           intPtr(inferTypeFromFramework(row, path)),
				Executable:     detectExecutable(path),
				Path:           path,
			}
			normalizeRecord(&record)
			out = append(out, record)
		}
	}
	return out
}

func collectFromProcesses(procs []processscan.ProcessInfo) []JarPackageRecord {
	out := make([]JarPackageRecord, 0)
	for _, proc := range procs {
		jarPaths := extractJarPathsFromProcess(proc)
		for _, jarPath := range jarPaths {
			path := normalizePath(jarPath)
			if path == nil {
				continue
			}
			name := nullableString(filepath.Base(*path))
			version := nullableString(detectVersionFromJarName(stringOrEmpty(name)))
			if version == nil {
				version = firstNonNilString(proc.PackageVersion, proc.Version)
			}

			record := JarPackageRecord{
				DisplayIP:      cloneStringPtr(proc.DisplayIP),
				ExternalIPList: cloneStrings(proc.ExternalIPList),
				InternalIPList: cloneStrings(proc.InternalIPList),
				BizGroupID:     cloneInt64Ptr(proc.BizGroupID),
				BizGroup:       cloneStringPtr(proc.BizGroup),
				Remark:         cloneStringPtr(proc.Remark),
				HostTagList:    cloneStrings(proc.HostTagList),
				Hostname:       cloneStringPtr(proc.Hostname),
				Name:           name,
				Version:        version,
				Type:           intPtr(inferTypeFromProcess(proc, path)),
				Executable:     detectExecutable(path),
				Path:           path,
			}
			normalizeRecord(&record)
			out = append(out, record)
		}
	}
	return out
}

func buildJarPath(absDir, jarName *string) *string {
	dir := stringOrEmpty(absDir)
	name := stringOrEmpty(jarName)
	switch {
	case dir != "" && name != "":
		return normalizePath(filepath.Join(dir, name))
	case name != "":
		return normalizePath(name)
	case dir != "":
		return normalizePath(dir)
	default:
		return nil
	}
}

func extractJarPathsFromProcess(proc processscan.ProcessInfo) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	appendPath := func(raw string) {
		if !looksLikeJarPath(raw) {
			return
		}
		resolved := resolveProcessJarPath(raw, proc.Path)
		normalized := normalizePath(resolved)
		if normalized == nil {
			return
		}
		// Re-validate after normalization because filepath cleaning can mutate
		// adversarial inputs into non-jar paths.
		if !looksLikeJarPath(*normalized) {
			return
		}
		key := strings.ToLower(*normalized)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, *normalized)
	}

	appendPath(stringOrEmpty(proc.Path))
	tokens := splitCommandLineLoose(stringOrEmpty(proc.StartArgs))
	for i, tok := range tokens {
		trimmed := strings.TrimSpace(strings.Trim(tok, `"'`))
		lower := strings.ToLower(trimmed)
		if lower == "-jar" && i+1 < len(tokens) {
			appendPath(tokens[i+1])
			continue
		}
		if strings.HasPrefix(lower, "-jar=") {
			appendPath(trimmed[len("-jar="):])
			continue
		}
		appendPath(trimmed)
	}
	return out
}

func looksLikeJarPath(raw string) bool {
	trimmed := strings.TrimSpace(strings.Trim(raw, `"'`))
	if trimmed == "" {
		return false
	}
	return strings.EqualFold(filepath.Ext(trimmed), ".jar")
}

func resolveProcessJarPath(raw string, procPath *string) string {
	trimmed := strings.TrimSpace(strings.Trim(raw, `"'`))
	if trimmed == "" {
		return ""
	}
	if filepath.IsAbs(trimmed) {
		return trimmed
	}
	if procPath == nil || strings.TrimSpace(*procPath) == "" {
		return trimmed
	}
	return filepath.Join(filepath.Dir(strings.TrimSpace(*procPath)), trimmed)
}

func inferTypeFromFramework(row webframescan.WebFrameRecord, path *string) int {
	meta := strings.ToLower(strings.TrimSpace(stringOrEmpty(row.ServerName) + " " + stringOrEmpty(row.Name) + " " + stringOrEmpty(row.Type)))
	if strings.Contains(meta, "tomcat") || strings.Contains(meta, "nginx") || strings.Contains(meta, "apache") || strings.Contains(meta, "httpd") || strings.Contains(meta, "iis") || strings.Contains(meta, "weblogic") || strings.Contains(meta, "jboss") || strings.Contains(meta, "wildfly") {
		return 3
	}
	if isSystemPath(path) {
		return 2
	}
	if isDependencyPath(path) {
		return 8
	}
	if strings.TrimSpace(meta) != "" {
		return 3
	}
	return 1
}

func inferTypeFromProcess(proc processscan.ProcessInfo, path *string) int {
	if isSystemPath(path) {
		return 2
	}
	meta := strings.ToLower(strings.TrimSpace(stringOrEmpty(proc.Name) + " " + stringOrEmpty(proc.Path) + " " + stringOrEmpty(proc.StartArgs)))
	if strings.Contains(meta, "tomcat") || strings.Contains(meta, "nginx") || strings.Contains(meta, "apache") || strings.Contains(meta, "httpd") || strings.Contains(meta, "iis") {
		return 3
	}
	if strings.Contains(meta, "java") {
		return 1
	}
	if isDependencyPath(path) {
		return 8
	}
	return 8
}

func isSystemPath(path *string) bool {
	if path == nil {
		return false
	}
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(*path), "\\", "/"))
	systemPrefixes := []string{
		"/usr/lib/",
		"/lib/",
		"/system/",
		"c:/windows/",
		"c:/program files/windows",
	}
	for _, prefix := range systemPrefixes {
		if strings.HasPrefix(normalized, prefix) {
			return true
		}
	}
	return false
}

func isDependencyPath(path *string) bool {
	if path == nil {
		return false
	}
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(*path), "\\", "/"))
	return strings.Contains(normalized, "/lib/") || strings.Contains(normalized, "/libs/")
}

func detectExecutable(path *string) *bool {
	if path == nil {
		return boolPtr(false)
	}
	info, err := os.Stat(*path)
	if err != nil {
		switch strings.ToLower(filepath.Ext(*path)) {
		case ".exe", ".bat", ".cmd", ".com", ".ps1":
			return boolPtr(true)
		default:
			return boolPtr(false)
		}
	}
	if info.Mode()&0o111 != 0 {
		return boolPtr(true)
	}
	switch strings.ToLower(filepath.Ext(*path)) {
	case ".exe", ".bat", ".cmd", ".com", ".ps1":
		return boolPtr(true)
	default:
		return boolPtr(false)
	}
}

func detectVersionFromJarName(name string) string {
	match := jarVersionRe.FindStringSubmatch(name)
	if len(match) > 1 {
		return match[1]
	}
	return ""
}

func mergeRows(rows []JarPackageRecord) []JarPackageRecord {
	if len(rows) == 0 {
		return []JarPackageRecord{}
	}
	indexByKey := map[string]int{}
	out := make([]JarPackageRecord, 0, len(rows))
	for _, row := range rows {
		normalizeRecord(&row)
		key := rowMergeKey(row)
		if idx, ok := indexByKey[key]; ok {
			merged := out[idx]
			merged.DisplayIP = firstNonNilString(merged.DisplayIP, row.DisplayIP)
			merged.ExternalIPList = mergeStringSlices(merged.ExternalIPList, row.ExternalIPList)
			merged.InternalIPList = mergeStringSlices(merged.InternalIPList, row.InternalIPList)
			merged.BizGroupID = firstNonNilInt64(merged.BizGroupID, row.BizGroupID)
			merged.BizGroup = firstNonNilString(merged.BizGroup, row.BizGroup)
			merged.Remark = firstNonNilString(merged.Remark, row.Remark)
			merged.HostTagList = mergeStringSlices(merged.HostTagList, row.HostTagList)
			merged.Hostname = firstNonNilString(merged.Hostname, row.Hostname)
			merged.Name = firstNonNilString(merged.Name, row.Name)
			merged.Version = firstNonNilString(merged.Version, row.Version)
			merged.Type = firstNonNilInt(merged.Type, row.Type)
			merged.Executable = firstNonNilBool(merged.Executable, row.Executable)
			merged.Path = firstNonNilString(merged.Path, row.Path)
			normalizeRecord(&merged)
			out[idx] = merged
			continue
		}

		indexByKey[key] = len(out)
		out = append(out, row)
	}

	sort.Slice(out, func(i, j int) bool {
		left := strings.ToLower(strings.TrimSpace(stringOrEmpty(out[i].Hostname) + "|" + stringOrEmpty(out[i].Name) + "|" + stringOrEmpty(out[i].Path)))
		right := strings.ToLower(strings.TrimSpace(stringOrEmpty(out[j].Hostname) + "|" + stringOrEmpty(out[j].Name) + "|" + stringOrEmpty(out[j].Path)))
		return left < right
	})
	return out
}

func rowMergeKey(row JarPackageRecord) string {
	return strings.ToLower(strings.TrimSpace(stringOrEmpty(row.Hostname) + "|" + stringOrEmpty(row.Name) + "|" + stringOrEmpty(row.Path)))
}

func normalizeRecord(row *JarPackageRecord) {
	if row.ExternalIPList == nil {
		row.ExternalIPList = []string{}
	}
	if row.InternalIPList == nil {
		row.InternalIPList = []string{}
	}
	if row.HostTagList == nil {
		row.HostTagList = []string{}
	}

	row.DisplayIP = cloneStringPtr(row.DisplayIP)
	row.BizGroupID = cloneInt64Ptr(row.BizGroupID)
	row.BizGroup = cloneStringPtr(row.BizGroup)
	row.Remark = cloneStringPtr(row.Remark)
	row.Hostname = cloneStringPtr(row.Hostname)
	row.Name = cloneStringPtr(row.Name)
	row.Version = cloneStringPtr(row.Version)
	row.Type = cloneIntPtr(row.Type)
	row.Executable = cloneBoolPtr(row.Executable)
	row.Path = cloneStringPtr(row.Path)

	if row.Path != nil {
		row.Path = normalizePath(*row.Path)
	}
	if row.Name == nil && row.Path != nil {
		row.Name = nullableString(filepath.Base(*row.Path))
	}
	if row.Version == nil {
		row.Version = nullableString(detectVersionFromJarName(stringOrEmpty(row.Name)))
	}
	if row.Type == nil {
		row.Type = intPtr(8)
	}
	if row.Executable == nil {
		row.Executable = boolPtr(false)
	}
}
