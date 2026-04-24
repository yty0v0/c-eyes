package websitescan

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"edrsystem/internal/processscan"
)

var listWebSiteProcessRowsFn = func(ctx context.Context) ([]processscan.ProcessInfo, error) {
	rows, err := processscan.Scan(ctx, processscan.ProcessScanParams{})
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func enrichWebSitesWithProcesses(ctx context.Context, rows []WebSiteInfo) []WebSiteInfo {
	procs, err := listWebSiteProcessRowsFn(ctx)
	if err != nil {
		return rows
	}

	for _, proc := range procs {
		kind, cfgPath := detectWebSiteProcessKindAndConfig(proc)
		if kind == "" {
			continue
		}
		cfgPath = normalizeWebSiteConfigPath(cfgPath, proc.Path)
		idx := findWebSiteRowIndex(rows, kind, cfgPath)
		if idx >= 0 {
			mergeWebSiteProcessMeta(&rows[idx], proc)
			continue
		}

		row, ok := buildWebSiteFromConfig(kind, cfgPath)
		if !ok {
			row = WebSiteInfo{
				Type:       strPtr(kind),
				ConfigName: nullableString(filepath.Base(cfgPath)),
			}
		}
		mergeWebSiteProcessMeta(&row, proc)
		normalizeDefaults(&row)
		rows = append(rows, row)
	}
	return dedupeWebSiteRows(rows)
}

func dedupeWebSiteRows(rows []WebSiteInfo) []WebSiteInfo {
	seen := map[string]struct{}{}
	out := make([]WebSiteInfo, 0, len(rows))
	for _, row := range rows {
		key := strings.ToLower(strings.TrimSpace(stringOrEmpty(row.Type))) + "|" +
			strings.ToLower(strings.TrimSpace(stringOrEmpty(row.ConfigName))) + "|" +
			strings.ToLower(strings.TrimSpace(physicalPathOf(row.Root))) + "|" +
			strings.ToLower(strings.TrimSpace(intString(row.Port)))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, row)
	}
	return out
}

func physicalPathOf(root *VirtualDirInfo) string {
	if root == nil || root.PhysicalPath == nil {
		return ""
	}
	return *root.PhysicalPath
}

func intString(v *int) string {
	if v == nil {
		return ""
	}
	return strconv.Itoa(*v)
}

func findWebSiteRowIndex(rows []WebSiteInfo, kind, cfgPath string) int {
	cfgName := strings.ToLower(strings.TrimSpace(filepath.Base(cfgPath)))
	for i := range rows {
		if !strings.EqualFold(stringOrEmpty(rows[i].Type), kind) {
			continue
		}
		if cfgName == "" {
			return i
		}
		if strings.EqualFold(strings.TrimSpace(stringOrEmpty(rows[i].ConfigName)), cfgName) {
			return i
		}
	}
	return -1
}

func mergeWebSiteProcessMeta(row *WebSiteInfo, proc processscan.ProcessInfo) {
	row.IsRunning = boolPtr(true)
	if row.PID == nil && proc.PID != nil {
		row.PID = intPtr(*proc.PID)
	}
	if row.Cmd == nil && proc.StartArgs != nil {
		row.Cmd = nullableString(*proc.StartArgs)
	}
	if row.User == nil && proc.Uname != nil {
		row.User = nullableString(*proc.Uname)
	}
	if row.Path == nil && proc.Path != nil {
		row.Path = nullableString(*proc.Path)
	}
}

func buildWebSiteFromConfig(kind, path string) (WebSiteInfo, bool) {
	if strings.TrimSpace(path) == "" {
		return WebSiteInfo{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return WebSiteInfo{}, false
	}
	content := string(data)
	switch kind {
	case "nginx":
		webRoot, domains, port, proto, allow, deny, sec := parseNginx(content)
		vd, root := rootVirtualDirForPath(webRoot)
		return WebSiteInfo{
			Type:            strPtr("nginx"),
			Port:            port,
			Proto:           nullableString(proto),
			Allow:           nullableString(allow),
			Deny:            nullableString(deny),
			SecurityEnabled: boolPtr(sec),
			Domains:         domains,
			VirtualDir:      vd,
			Root:            root,
			Path:            nullableString(webRoot),
			ConfigName:      nullableString(filepath.Base(path)),
		}, true
	case "apache":
		webRoot, domains, port, proto := parseApache(content)
		vd, root := rootVirtualDirForPath(webRoot)
		return WebSiteInfo{
			Type:       strPtr("apache"),
			Port:       port,
			Proto:      nullableString(proto),
			Domains:    domains,
			VirtualDir: vd,
			Root:       root,
			Path:       nullableString(webRoot),
			ConfigName: nullableString(filepath.Base(path)),
		}, true
	case "tomcat":
		webRoot, domains, port, proto := parseTomcat(content)
		vd, root := rootVirtualDirForPath(webRoot)
		return WebSiteInfo{
			Type:       strPtr("tomcat"),
			Port:       port,
			Proto:      nullableString(proto),
			Domains:    domains,
			VirtualDir: vd,
			Root:       root,
			Path:       nullableString(webRoot),
			DeployPath: nullableString(filepath.Dir(webRoot)),
			ConfigName: nullableString(filepath.Base(path)),
		}, true
	case "iis":
		rows := parseIISApplicationHost(data)
		if len(rows) == 0 {
			return WebSiteInfo{}, false
		}
		return rows[0], true
	default:
		return WebSiteInfo{}, false
	}
}

func detectWebSiteProcessKindAndConfig(proc processscan.ProcessInfo) (kind, cfgPath string) {
	fields := []string{
		stringOrEmpty(proc.Name),
		stringOrEmpty(proc.Path),
		stringOrEmpty(proc.StartArgs),
	}
	joined := strings.ToLower(strings.Join(fields, " "))
	switch {
	case strings.Contains(joined, "nginx"):
		kind = "nginx"
	case strings.Contains(joined, "httpd"), strings.Contains(joined, "apache"):
		kind = "apache"
	case strings.Contains(joined, "tomcat"), strings.Contains(joined, "catalina"):
		kind = "tomcat"
	case strings.Contains(joined, "w3wp"), strings.Contains(joined, "iis"):
		kind = "iis"
	default:
		return "", ""
	}

	cfgPath = extractConfigPathFromArgs(kind, stringOrEmpty(proc.StartArgs))
	if cfgPath == "" {
		cfgPath = extractConfigPathFromArgs(kind, stringOrEmpty(proc.Path))
	}
	return kind, cfgPath
}

func normalizeWebSiteConfigPath(path string, exePath *string) string {
	trimmed := strings.TrimSpace(strings.Trim(path, `"'`))
	if trimmed == "" {
		return ""
	}
	if filepath.IsAbs(trimmed) {
		return resolveWebSiteSymlinkPath(trimmed)
	}
	if exePath == nil || strings.TrimSpace(*exePath) == "" {
		return resolveWebSiteSymlinkPath(trimmed)
	}
	return resolveWebSiteSymlinkPath(filepath.Join(filepath.Dir(strings.TrimSpace(*exePath)), trimmed))
}

func extractConfigPathFromArgs(kind, raw string) string {
	tokens := splitCommandLineLoose(raw)
	if len(tokens) == 0 {
		return ""
	}
	for i := 0; i < len(tokens); i++ {
		tok := strings.Trim(tokens[i], `"'`)
		lower := strings.ToLower(tok)
		if (lower == "-c" || lower == "-f" || lower == "--config") && i+1 < len(tokens) {
			return strings.Trim(tokens[i+1], `"'`)
		}
		if strings.HasPrefix(lower, "-c=") || strings.HasPrefix(lower, "-f=") || strings.HasPrefix(lower, "--config=") {
			idx := strings.Index(tok, "=")
			if idx >= 0 {
				return strings.Trim(tok[idx+1:], `"'`)
			}
		}
		if looksLikeConfigFile(lower, kind) {
			return tok
		}
	}
	return ""
}

func looksLikeConfigFile(path, kind string) bool {
	switch kind {
	case "nginx":
		return strings.HasSuffix(path, "nginx.conf")
	case "apache":
		return strings.HasSuffix(path, "httpd.conf") || strings.HasSuffix(path, "apache2.conf")
	case "tomcat":
		return strings.HasSuffix(path, "server.xml")
	case "iis":
		return strings.HasSuffix(path, "applicationhost.config")
	default:
		return false
	}
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
