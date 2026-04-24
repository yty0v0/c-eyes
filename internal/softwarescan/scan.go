package softwarescan

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"edrsystem/internal/processscan"
)

var (
	collectSoftwareFn = collectSoftware
	scanProcessFn     = func(ctx context.Context) ([]processscan.ProcessInfo, error) {
		return processscan.Scan(ctx, processscan.ProcessScanParams{})
	}
	getHostInfoFn = processscan.GetHostInfo
)

var knownSoftwareNames = map[string]struct{}{
	"nginx":      {},
	"apache":     {},
	"tomcat":     {},
	"iis":        {},
	"java":       {},
	"mysql":      {},
	"postgresql": {},
	"redis":      {},
	"mongodb":    {},
	"python":     {},
	"php":        {},
	"dotnet":     {},
	"node":       {},
}

// Scan collects and filters software information.
func Scan(ctx context.Context, params SoftwareScanParams) (SoftwareScanResult, error) {
	rows, err := collectSoftwareFn(ctx)
	if err != nil {
		return SoftwareScanResult{}, err
	}
	rows = mergeRows(rows)

	host, _ := getHostInfoFn()
	total := len(rows)
	for i := range rows {
		applyHost(&rows[i], host)
		normalizeRecord(&rows[i])
		if params.Progress != nil {
			params.Progress(i+1, total, "collect_software")
		}
	}

	filtered := ApplyFilters(rows, params, host)
	if params.Progress != nil {
		params.Progress(total, total, "complete")
	}

	return SoftwareScanResult{
		Total: len(filtered),
		Rows:  filtered,
	}, nil
}

func collectSoftwareFromProcesses(ctx context.Context) ([]SoftwareInfo, error) {
	procs, err := scanProcessFn(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]SoftwareInfo, 0, len(procs))
	for _, proc := range procs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row, ok := softwareFromProcess(proc)
		if !ok {
			continue
		}
		out = append(out, row)
	}
	return out, nil
}

func softwareFromProcess(proc processscan.ProcessInfo) (SoftwareInfo, bool) {
	name := detectSoftwareName(proc)
	configPath := extractConfigPath(stringOrEmpty(proc.StartArgs), proc.Path)
	binPath := normalizePathPtr(proc.Path)
	if !isLikelyServiceProcess(proc, name, configPath) {
		return SoftwareInfo{}, false
	}

	processName := cloneStringPtr(proc.Name)
	if processName == nil {
		processName = nullableString(name)
	}
	row := SoftwareInfo{
		Name:       nullableString(name),
		Version:    firstNonNilString(proc.PackageVersion, proc.Version),
		Uname:      cloneStringPtr(proc.Uname),
		BinPath:    binPath,
		ConfigPath: configPath,
		Processes: []SoftwareProcess{
			{
				PID:   cloneIntPtr(proc.PID),
				Name:  processName,
				Uname: cloneStringPtr(proc.Uname),
			},
		},
	}
	return row, true
}

func isLikelyServiceProcess(proc processscan.ProcessInfo, normalizedName string, configPath *string) bool {
	if normalizedName != "" {
		if _, ok := knownSoftwareNames[normalizedName]; ok {
			return true
		}
	}
	if configPath != nil {
		return true
	}

	meta := strings.ToLower(strings.TrimSpace(
		normalizedName + " " +
			stringOrEmpty(proc.Name) + " " +
			stringOrEmpty(proc.Path) + " " +
			stringOrEmpty(proc.StartArgs),
	))
	return strings.Contains(meta, "service") ||
		strings.Contains(meta, "daemon") ||
		strings.Contains(meta, "server")
}

func detectSoftwareName(proc processscan.ProcessInfo) string {
	nameRaw := strings.TrimSpace(stringOrEmpty(proc.Name))
	pathRaw := strings.TrimSpace(stringOrEmpty(proc.Path))
	name := strings.ToLower(nameRaw)
	path := strings.ToLower(pathRaw)
	javaLike := false

	for _, token := range []string{name, path} {
		if normalized := detectSoftwareNameToken(token); normalized != "" {
			if normalized == "java" {
				javaLike = true
			} else {
				return normalized
			}
		}
		base := strings.ToLower(strings.TrimSpace(filepath.Base(token)))
		if normalized := detectSoftwareNameToken(base); normalized != "" {
			if normalized == "java" {
				javaLike = true
			} else {
				return normalized
			}
		}
	}

	// Keep limited arg-based fallback for Java/Tomcat runtimes only.
	if javaLike || strings.Contains(name, "java") || strings.Contains(path, "java") {
		args := strings.ToLower(strings.TrimSpace(stringOrEmpty(proc.StartArgs)))
		if strings.Contains(args, "org.apache.catalina.startup.bootstrap") ||
			strings.Contains(args, "catalina.base") ||
			strings.Contains(args, "catalina.home") {
			return "tomcat"
		}
		return "java"
	}

	if normalized := normalizeNameFromPathOrLabel(nameRaw); normalized != "" {
		return normalized
	}
	if normalized := normalizeNameFromPathOrLabel(filepath.Base(pathRaw)); normalized != "" {
		return normalized
	}
	return ""
}

func detectSoftwareNameToken(token string) string {
	switch {
	case strings.Contains(token, "nginx"):
		return "nginx"
	case strings.Contains(token, "apache"), strings.Contains(token, "httpd"):
		return "apache"
	case strings.Contains(token, "tomcat"), strings.Contains(token, "catalina"):
		return "tomcat"
	case strings.Contains(token, "w3wp"), strings.Contains(token, "iis"):
		return "iis"
	case strings.Contains(token, "mysqld"), strings.Contains(token, "mysql"):
		return "mysql"
	case strings.Contains(token, "postgres"), strings.Contains(token, "postgresql"):
		return "postgresql"
	case strings.Contains(token, "redis"):
		return "redis"
	case strings.Contains(token, "mongod"), strings.Contains(token, "mongodb"):
		return "mongodb"
	case strings.Contains(token, "php"):
		return "php"
	case strings.Contains(token, "dotnet"), strings.Contains(token, "aspnet"):
		return "dotnet"
	case strings.Contains(token, "python"), strings.Contains(token, "gunicorn"), strings.Contains(token, "uwsgi"):
		return "python"
	case strings.Contains(token, "node"), strings.Contains(token, "pm2"):
		return "node"
	case strings.Contains(token, "java"):
		return "java"
	default:
		return ""
	}
}

func normalizeNameFromPathOrLabel(raw string) string {
	trimmed := strings.TrimSpace(strings.Trim(raw, `"'`))
	if trimmed == "" {
		return ""
	}
	base := strings.ToLower(strings.TrimSpace(filepath.Base(trimmed)))
	base = strings.TrimSuffix(base, filepath.Ext(base))
	base = strings.TrimSuffix(base, "-service")
	base = strings.TrimSuffix(base, "_service")
	return strings.TrimSpace(base)
}

func extractConfigPath(raw string, exePath *string) *string {
	tokens := splitCommandLineLoose(raw)
	for i := 0; i < len(tokens); i++ {
		tok := strings.Trim(tokens[i], `"'`)
		lower := strings.ToLower(tok)
		if (lower == "-c" || lower == "-f" || lower == "--config") && i+1 < len(tokens) {
			return normalizeConfigPath(tokens[i+1], exePath)
		}
		if strings.HasPrefix(lower, "-c=") ||
			strings.HasPrefix(lower, "-f=") ||
			strings.HasPrefix(lower, "--config=") {
			idx := strings.Index(tok, "=")
			if idx >= 0 {
				return normalizeConfigPath(tok[idx+1:], exePath)
			}
		}
		if looksLikeConfigFile(lower) {
			return normalizeConfigPath(tok, exePath)
		}
	}
	return nil
}

func looksLikeConfigFile(path string) bool {
	switch {
	case strings.HasSuffix(path, ".conf"),
		strings.HasSuffix(path, ".cnf"),
		strings.HasSuffix(path, ".ini"),
		strings.HasSuffix(path, ".cfg"),
		strings.HasSuffix(path, ".yaml"),
		strings.HasSuffix(path, ".yml"),
		strings.HasSuffix(path, ".xml"),
		strings.HasSuffix(path, ".json"),
		strings.HasSuffix(path, "applicationhost.config"),
		strings.HasSuffix(path, "nginx.conf"),
		strings.HasSuffix(path, "httpd.conf"),
		strings.HasSuffix(path, "apache2.conf"),
		strings.HasSuffix(path, "server.xml"),
		strings.HasSuffix(path, "my.cnf"),
		strings.HasSuffix(path, "redis.conf"):
		return true
	default:
		return false
	}
}

func normalizeConfigPath(path string, exePath *string) *string {
	trimmed := strings.TrimSpace(strings.Trim(path, `"'`))
	if trimmed == "" {
		return nil
	}
	if filepath.IsAbs(trimmed) {
		return normalizePath(trimmed)
	}
	if exePath == nil || strings.TrimSpace(*exePath) == "" {
		return normalizePath(trimmed)
	}
	return normalizePath(filepath.Join(filepath.Dir(strings.TrimSpace(*exePath)), trimmed))
}

func splitCommandLineLoose(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	out := make([]string, 0, 8)
	var b strings.Builder
	quote := rune(0)
	flush := func() {
		if b.Len() == 0 {
			return
		}
		out = append(out, b.String())
		b.Reset()
	}

	for _, r := range raw {
		if quote != 0 {
			if r == quote {
				quote = 0
				continue
			}
			b.WriteRune(r)
			continue
		}
		if r == '"' || r == '\'' {
			quote = r
			continue
		}
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			flush()
			continue
		}
		b.WriteRune(r)
	}
	flush()
	return out
}

func mergeRows(rows []SoftwareInfo) []SoftwareInfo {
	if len(rows) == 0 {
		return []SoftwareInfo{}
	}

	indexByKey := make(map[string]int, len(rows))
	out := make([]SoftwareInfo, 0, len(rows))
	for i, row := range rows {
		normalizeRecord(&row)
		key := rowMergeKey(row)
		if key == "||" {
			key = fmt.Sprintf("row:%d", i)
		}
		if idx, ok := indexByKey[key]; ok {
			merged := out[idx]
			merged.ExternalIPList = mergeStringSlices(merged.ExternalIPList, row.ExternalIPList)
			merged.InternalIPList = mergeStringSlices(merged.InternalIPList, row.InternalIPList)
			merged.BizGroupID = firstNonNilInt64(merged.BizGroupID, row.BizGroupID)
			merged.BizGroup = firstNonNilString(merged.BizGroup, row.BizGroup)
			merged.Remark = firstNonNilString(merged.Remark, row.Remark)
			merged.HostTagList = mergeStringSlices(merged.HostTagList, row.HostTagList)
			merged.Hostname = firstNonNilString(merged.Hostname, row.Hostname)
			merged.Name = firstNonNilString(merged.Name, row.Name)
			merged.Version = firstNonNilString(merged.Version, row.Version)
			merged.Uname = firstNonNilString(merged.Uname, row.Uname)
			merged.BinPath = firstNonNilString(merged.BinPath, row.BinPath)
			merged.ConfigPath = firstNonNilString(merged.ConfigPath, row.ConfigPath)
			merged.Processes = mergeProcesses(merged.Processes, row.Processes)
			normalizeRecord(&merged)
			out[idx] = merged
			continue
		}

		indexByKey[key] = len(out)
		out = append(out, row)
	}

	sort.Slice(out, func(i, j int) bool {
		left := strings.ToLower(strings.TrimSpace(
			stringOrEmpty(out[i].Hostname) + "|" +
				stringOrEmpty(out[i].Name) + "|" +
				stringOrEmpty(out[i].BinPath) + "|" +
				stringOrEmpty(out[i].ConfigPath),
		))
		right := strings.ToLower(strings.TrimSpace(
			stringOrEmpty(out[j].Hostname) + "|" +
				stringOrEmpty(out[j].Name) + "|" +
				stringOrEmpty(out[j].BinPath) + "|" +
				stringOrEmpty(out[j].ConfigPath),
		))
		return left < right
	})
	return out
}

func rowMergeKey(row SoftwareInfo) string {
	return strings.ToLower(strings.TrimSpace(
		stringOrEmpty(row.Name) + "|" +
			stringOrEmpty(row.BinPath) + "|" +
			stringOrEmpty(row.ConfigPath),
	))
}

func applyHost(row *SoftwareInfo, host processscan.HostInfo) {
	row.ExternalIPList = mergeStringSlices(row.ExternalIPList, host.ExternalIPs)
	row.InternalIPList = mergeStringSlices(row.InternalIPList, host.InternalIPs)
	if row.BizGroupID == nil && host.BizGroupID != nil {
		row.BizGroupID = host.BizGroupID
	}
	if row.BizGroup == nil && host.BizGroup != nil {
		row.BizGroup = host.BizGroup
	}
	if row.Remark == nil && host.Remark != nil {
		row.Remark = host.Remark
	}
	if row.HostTagList == nil || len(row.HostTagList) == 0 {
		row.HostTagList = mergeStringSlices(row.HostTagList, host.HostTagList)
	}
	if row.Hostname == nil && strings.TrimSpace(host.Hostname) != "" {
		row.Hostname = strPtr(strings.TrimSpace(host.Hostname))
	}
}

func normalizeRecord(row *SoftwareInfo) {
	if row.ExternalIPList == nil {
		row.ExternalIPList = []string{}
	}
	if row.InternalIPList == nil {
		row.InternalIPList = []string{}
	}
	if row.HostTagList == nil {
		row.HostTagList = []string{}
	}
	if row.Processes == nil {
		row.Processes = []SoftwareProcess{}
	}

	row.ExternalIPList = mergeStringSlices(row.ExternalIPList, nil)
	row.InternalIPList = mergeStringSlices(row.InternalIPList, nil)
	row.HostTagList = mergeStringSlices(row.HostTagList, nil)

	row.BizGroupID = cloneInt64Ptr(row.BizGroupID)
	row.BizGroup = cloneStringPtr(row.BizGroup)
	row.Remark = cloneStringPtr(row.Remark)
	row.Hostname = cloneStringPtr(row.Hostname)
	row.Name = cloneStringPtr(row.Name)
	row.Version = cloneStringPtr(row.Version)
	row.Uname = cloneStringPtr(row.Uname)
	row.BinPath = normalizePathPtr(row.BinPath)
	row.ConfigPath = normalizePathPtr(row.ConfigPath)

	row.Processes = normalizeProcesses(row.Processes)
	if row.Uname == nil {
		for _, proc := range row.Processes {
			if proc.Uname != nil {
				row.Uname = cloneStringPtr(proc.Uname)
				break
			}
		}
	}
	if row.Name == nil && row.BinPath != nil {
		row.Name = nullableString(filepath.Base(*row.BinPath))
	}
}

func normalizeProcesses(processes []SoftwareProcess) []SoftwareProcess {
	if len(processes) == 0 {
		return []SoftwareProcess{}
	}
	out := make([]SoftwareProcess, 0, len(processes))
	seen := map[string]struct{}{}
	for _, proc := range processes {
		item := SoftwareProcess{
			PID:   cloneIntPtr(proc.PID),
			Name:  cloneStringPtr(proc.Name),
			Uname: cloneStringPtr(proc.Uname),
		}
		key := processMergeKey(item)
		if key == "||" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		leftPID := -1
		if out[i].PID != nil {
			leftPID = *out[i].PID
		}
		rightPID := -1
		if out[j].PID != nil {
			rightPID = *out[j].PID
		}
		if leftPID != rightPID {
			return leftPID < rightPID
		}
		left := strings.ToLower(strings.TrimSpace(
			stringOrEmpty(out[i].Name) + "|" + stringOrEmpty(out[i].Uname),
		))
		right := strings.ToLower(strings.TrimSpace(
			stringOrEmpty(out[j].Name) + "|" + stringOrEmpty(out[j].Uname),
		))
		return left < right
	})
	return out
}

func mergeProcesses(a, b []SoftwareProcess) []SoftwareProcess {
	joined := append([]SoftwareProcess{}, a...)
	joined = append(joined, b...)
	return normalizeProcesses(joined)
}

func processMergeKey(proc SoftwareProcess) string {
	pid := ""
	if proc.PID != nil {
		pid = strconv.Itoa(*proc.PID)
	}
	return strings.ToLower(strings.TrimSpace(
		pid + "|" + stringOrEmpty(proc.Name) + "|" + stringOrEmpty(proc.Uname),
	))
}

func int64InSlice(val int64, list []int64) bool {
	for _, item := range list {
		if item == val {
			return true
		}
	}
	return false
}

func stringInSliceFold(val string, list []string) bool {
	target := strings.ToLower(strings.TrimSpace(val))
	for _, item := range list {
		if target == strings.ToLower(strings.TrimSpace(item)) {
			return true
		}
	}
	return false
}

func stringOrEmpty(v *string) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(*v)
}

func nullableString(v string) *string {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return nil
	}
	return strPtr(trimmed)
}

func normalizePath(path string) *string {
	trimmed := strings.TrimSpace(strings.Trim(path, `"'`))
	if trimmed == "" {
		return nil
	}
	cleaned := filepath.Clean(trimmed)
	return nullableString(cleaned)
}

func normalizePathPtr(v *string) *string {
	if v == nil {
		return nil
	}
	return normalizePath(*v)
}

func mergeStringSlices(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return []string{}
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(a)+len(b))
	appendAll := func(list []string) {
		for _, item := range list {
			trimmed := strings.TrimSpace(item)
			if trimmed == "" {
				continue
			}
			key := strings.ToLower(trimmed)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, trimmed)
		}
	}
	appendAll(a)
	appendAll(b)
	sort.Strings(out)
	return out
}

func cloneStringPtr(v *string) *string {
	if v == nil {
		return nil
	}
	return nullableString(*v)
}

func cloneIntPtr(v *int) *int {
	if v == nil {
		return nil
	}
	return intPtr(*v)
}

func cloneInt64Ptr(v *int64) *int64 {
	if v == nil {
		return nil
	}
	return int64Ptr(*v)
}

func firstNonNilString(a, b *string) *string {
	if clone := cloneStringPtr(a); clone != nil {
		return clone
	}
	return cloneStringPtr(b)
}

func firstNonNilInt64(a, b *int64) *int64 {
	if clone := cloneInt64Ptr(a); clone != nil {
		return clone
	}
	return cloneInt64Ptr(b)
}
