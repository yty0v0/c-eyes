package webframescan

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"edrsystem/internal/webapplicationscan"
)

var (
	scanWebApplicationsFn = webapplicationscan.Scan
	listJarFromConfigFn   = listJarFromConfigPath
	jarVersionRe          = regexp.MustCompile(`([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
)

// Scan collects and filters web framework information.
func Scan(ctx context.Context, params WebFrameScanParams) (WebFrameScanResult, error) {
	appParams := webapplicationscan.WebApplicationScanParams{
		Groups:     append([]int64(nil), params.Groups...),
		Hostname:   cloneStringPtr(params.Hostname),
		IP:         cloneStringPtr(params.IP),
		ServerName: append([]string(nil), params.ServerName...),
	}
	if name := cloneStringPtr(params.Name); name != nil {
		appParams.AppName = name
	}
	if version := cloneStringPtr(params.Version); version != nil {
		appParams.Version = []string{*version}
	}
	if params.Progress != nil {
		appParams.Progress = func(done, total int, stage string) {
			params.Progress(done, total, stage)
		}
	}

	appResult, err := scanWebApplicationsFn(ctx, appParams)
	if err != nil {
		return WebFrameScanResult{}, err
	}

	rows := make([]WebFrameRecord, 0, len(appResult.Rows))
	total := len(appResult.Rows)
	for i := range appResult.Rows {
		row := mapRecord(appResult.Rows[i])
		normalizeRecord(&row)
		rows = append(rows, row)
		if params.Progress != nil {
			params.Progress(i+1, total, "normalize_web_framework")
		}
	}

	merged := mergeRows(rows)
	filtered := applyFilters(merged, params)
	if params.Progress != nil {
		params.Progress(total, total, "complete")
	}

	return WebFrameScanResult{
		Total: len(filtered),
		Rows:  filtered,
	}, nil
}

func mapRecord(src webapplicationscan.WebApplicationInfo) WebFrameRecord {
	webAppDir := cloneStringPtr(src.RootPath)
	webRoot := cloneStringPtr(src.WebRoot)
	frameworkType := inferFrameworkType(src)
	jarList := collectJarRecords(src)
	jarCount := strPtr(strconv.Itoa(len(jarList)))

	return WebFrameRecord{
		DisplayIP:      cloneStringPtr(src.DisplayIP),
		ExternalIPList: cloneStrings(src.ExternalIPList),
		InternalIPList: cloneStrings(src.InternalIPList),
		BizGroupID:     src.BizGroupID,
		BizGroup:       cloneStringPtr(src.BizGroup),
		Remark:         cloneStringPtr(src.Remark),
		HostTagList:    cloneStrings(src.HostTagList),
		Hostname:       cloneStringPtr(src.Hostname),
		Name:           firstNonNil(src.AppName, src.ServerName),
		Version:        cloneStringPtr(src.Version),
		Type:           frameworkType,
		ServerName:     cloneStringPtr(src.ServerName),
		DomainName:     cloneStringPtr(src.DomainName),
		WebAppDir:      webAppDir,
		JarCount:       jarCount,
		JarList:        jarList,
		WebRoot:        webRoot,
		WorkDir:        deriveWorkDir(webRoot, webAppDir),
	}
}

func normalizeRecord(row *WebFrameRecord) {
	if row.ExternalIPList == nil {
		row.ExternalIPList = []string{}
	}
	if row.InternalIPList == nil {
		row.InternalIPList = []string{}
	}
	if row.HostTagList == nil {
		row.HostTagList = []string{}
	}
	if row.JarList == nil {
		row.JarList = []JarRecord{}
	}
	row.Name = cloneStringPtr(row.Name)
	row.Version = cloneStringPtr(row.Version)
	row.Type = cloneStringPtr(row.Type)
	row.ServerName = cloneStringPtr(row.ServerName)
	row.DomainName = cloneStringPtr(row.DomainName)
	row.WebAppDir = cloneStringPtr(row.WebAppDir)
	row.WebRoot = cloneStringPtr(row.WebRoot)
	row.WorkDir = deriveWorkDir(row.WebRoot, row.WebAppDir)
	for i := range row.JarList {
		row.JarList[i].Version = cloneStringPtr(row.JarList[i].Version)
		row.JarList[i].AbsDir = cloneStringPtr(row.JarList[i].AbsDir)
		row.JarList[i].JarName = cloneStringPtr(row.JarList[i].JarName)
	}
	if row.JarCount == nil {
		row.JarCount = strPtr(strconv.Itoa(len(row.JarList)))
	}
}

func inferFrameworkType(src webapplicationscan.WebApplicationInfo) *string {
	value := strings.ToLower(strings.TrimSpace(stringOrEmpty(src.ServerName) + " " + stringOrEmpty(src.AppName)))
	switch {
	case strings.Contains(value, "tomcat"), strings.Contains(value, "java"):
		return strPtr("java")
	case strings.Contains(value, "django"), strings.Contains(value, "flask"), strings.Contains(value, "python"), strings.Contains(value, "gunicorn"):
		return strPtr("python")
	case strings.Contains(value, "php"), strings.Contains(value, "nginx"), strings.Contains(value, "apache"), strings.Contains(value, "iis"):
		return strPtr("php")
	default:
		return nil
	}
}

func collectJarRecords(src webapplicationscan.WebApplicationInfo) []JarRecord {
	seen := map[string]struct{}{}
	out := make([]JarRecord, 0, len(src.Plugins))
	appendJar := func(j JarRecord) {
		key := strings.ToLower(strings.TrimSpace(stringOrEmpty(j.AbsDir) + "|" + stringOrEmpty(j.JarName) + "|" + stringOrEmpty(j.Version)))
		if key == "||" {
			return
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, j)
	}

	for _, plugin := range src.Plugins {
		if jar, ok := pluginToJar(plugin); ok {
			appendJar(jar)
		}
	}

	if server := strings.ToLower(stringOrEmpty(src.ServerName)); strings.Contains(server, "tomcat") {
		for _, jar := range listJarFromConfigFn(stringOrEmpty(src.RootPath)) {
			appendJar(jar)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		left := strings.ToLower(stringOrEmpty(out[i].JarName))
		right := strings.ToLower(stringOrEmpty(out[j].JarName))
		if left != right {
			return left < right
		}
		return strings.ToLower(stringOrEmpty(out[i].AbsDir)) < strings.ToLower(stringOrEmpty(out[j].AbsDir))
	})
	return out
}

func pluginToJar(plugin webapplicationscan.PluginInfo) (JarRecord, bool) {
	candidateName := stringOrEmpty(plugin.PluginName)
	candidatePath := ""
	for _, raw := range []string{stringOrEmpty(plugin.PluginURI), stringOrEmpty(plugin.Description), candidateName} {
		token := extractJarToken(raw)
		if token != "" {
			candidatePath = token
			break
		}
	}

	if candidatePath == "" && !strings.HasSuffix(strings.ToLower(candidateName), ".jar") {
		return JarRecord{}, false
	}

	jarName := candidateName
	absDir := ""
	if candidatePath != "" {
		jarName = filepath.Base(candidatePath)
		if dir := filepath.Dir(candidatePath); dir != "." && dir != "" {
			absDir = dir
		}
	}
	if !strings.HasSuffix(strings.ToLower(jarName), ".jar") {
		return JarRecord{}, false
	}

	version := stringOrEmpty(plugin.Version)
	if strings.TrimSpace(version) == "" {
		version = detectVersionFromJarName(jarName)
	}
	return JarRecord{
		Version: nullableString(version),
		AbsDir:  nullableString(absDir),
		JarName: nullableString(jarName),
	}, true
}

func extractJarToken(raw string) string {
	cleaned := strings.TrimSpace(strings.Trim(raw, `"'`))
	if cleaned == "" {
		return ""
	}
	tokens := strings.FieldsFunc(cleaned, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == ';' || r == ','
	})
	for _, token := range tokens {
		trimmed := strings.Trim(token, `"'`)
		if strings.HasSuffix(strings.ToLower(trimmed), ".jar") {
			return trimmed
		}
	}
	if strings.HasSuffix(strings.ToLower(cleaned), ".jar") {
		return cleaned
	}
	return ""
}

func listJarFromConfigPath(configPath string) []JarRecord {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return nil
	}
	confDir := filepath.Dir(configPath)
	if strings.EqualFold(filepath.Base(confDir), "conf") {
		base := filepath.Dir(confDir)
		return listJarInDir(filepath.Join(base, "lib"))
	}
	return nil
}

func listJarInDir(dir string) []JarRecord {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := make([]JarRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.TrimSpace(entry.Name())
		if !strings.HasSuffix(strings.ToLower(name), ".jar") {
			continue
		}
		out = append(out, JarRecord{
			Version: nullableString(detectVersionFromJarName(name)),
			AbsDir:  nullableString(dir),
			JarName: nullableString(name),
		})
	}
	return out
}

func detectVersionFromJarName(name string) string {
	match := jarVersionRe.FindStringSubmatch(name)
	if len(match) > 1 {
		return match[1]
	}
	return ""
}

func mergeRows(rows []WebFrameRecord) []WebFrameRecord {
	if len(rows) < 2 {
		return rows
	}
	indexByKey := map[string]int{}
	out := make([]WebFrameRecord, 0, len(rows))

	for _, row := range rows {
		key := rowMergeKey(row)
		if idx, ok := indexByKey[key]; ok {
			merged := out[idx]
			merged.DisplayIP = firstNonNil(merged.DisplayIP, row.DisplayIP)
			merged.BizGroup = firstNonNil(merged.BizGroup, row.BizGroup)
			if merged.BizGroupID == nil {
				merged.BizGroupID = row.BizGroupID
			}
			merged.Remark = firstNonNil(merged.Remark, row.Remark)
			merged.Hostname = firstNonNil(merged.Hostname, row.Hostname)
			merged.Name = firstNonNil(merged.Name, row.Name)
			merged.Version = firstNonNil(merged.Version, row.Version)
			merged.Type = firstNonNil(merged.Type, row.Type)
			merged.ServerName = firstNonNil(merged.ServerName, row.ServerName)
			merged.DomainName = firstNonNil(merged.DomainName, row.DomainName)
			merged.WebAppDir = firstNonNil(merged.WebAppDir, row.WebAppDir)
			merged.WebRoot = firstNonNil(merged.WebRoot, row.WebRoot)
			merged.WorkDir = deriveWorkDir(merged.WebRoot, merged.WebAppDir)
			merged.ExternalIPList = mergeStringSlices(merged.ExternalIPList, row.ExternalIPList)
			merged.InternalIPList = mergeStringSlices(merged.InternalIPList, row.InternalIPList)
			merged.HostTagList = mergeStringSlices(merged.HostTagList, row.HostTagList)
			merged.JarList = mergeJarList(merged.JarList, row.JarList)
			merged.JarCount = strPtr(strconv.Itoa(len(merged.JarList)))
			normalizeRecord(&merged)
			out[idx] = merged
			continue
		}
		rowCopy := row
		normalizeRecord(&rowCopy)
		indexByKey[key] = len(out)
		out = append(out, rowCopy)
	}

	return out
}

func rowMergeKey(row WebFrameRecord) string {
	return strings.ToLower(strings.TrimSpace(stringOrEmpty(row.Hostname) + "|" + stringOrEmpty(row.Name) + "|" + stringOrEmpty(row.ServerName) + "|" + stringOrEmpty(row.WebAppDir)))
}

func mergeJarList(a, b []JarRecord) []JarRecord {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]JarRecord, 0, len(a)+len(b))
	appendAll := func(list []JarRecord) {
		for _, item := range list {
			key := strings.ToLower(strings.TrimSpace(stringOrEmpty(item.AbsDir) + "|" + stringOrEmpty(item.JarName) + "|" + stringOrEmpty(item.Version)))
			if key == "||" {
				continue
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, JarRecord{
				Version: cloneStringPtr(item.Version),
				AbsDir:  cloneStringPtr(item.AbsDir),
				JarName: cloneStringPtr(item.JarName),
			})
		}
	}
	appendAll(a)
	appendAll(b)
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(stringOrEmpty(out[i].JarName)) < strings.ToLower(stringOrEmpty(out[j].JarName))
	})
	return out
}
