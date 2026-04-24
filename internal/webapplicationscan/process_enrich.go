package webapplicationscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"edrsystem/internal/processscan"
)

var listProcessRowsFn = func(ctx context.Context) ([]processscan.ProcessInfo, error) {
	result, err := processscan.Scan(ctx, processscan.ProcessScanParams{})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func enrichWebApplicationsWithProcesses(ctx context.Context, rows []WebApplicationInfo) []WebApplicationInfo {
	procs, err := listProcessRowsFn(ctx)
	if err != nil {
		return rows
	}

	seen := map[string]struct{}{}
	indexByKind := map[string]int{}
	for i := range rows {
		kind := normalizeWebKind(rows[i].ServerName, rows[i].AppName)
		rootPath := strings.ToLower(strings.TrimSpace(stringOrEmpty(rows[i].RootPath)))
		seen[kind+"|"+rootPath] = struct{}{}
		if _, ok := indexByKind[kind]; !ok && kind != "" {
			indexByKind[kind] = i
		}
	}

	for _, proc := range procs {
		kind, cfgPath := detectWebProcessKindAndConfig(proc)
		if kind == "" {
			continue
		}
		cfgPath = normalizeConfigPath(cfgPath, proc.Path)
		meta := inspectWebConfig(kind, cfgPath)

		if idx, ok := indexByKind[kind]; ok {
			mergeWebAppProcessMeta(&rows[idx], proc, cfgPath, meta)
			continue
		}

		row := WebApplicationInfo{
			AppName:     strPtr(kind),
			ServerName:  strPtr(kind),
			Description: strPtr("Detected from running process"),
			Plugins:     []PluginInfo{},
		}
		mergeWebAppProcessMeta(&row, proc, cfgPath, meta)
		key := kind + "|" + strings.ToLower(strings.TrimSpace(stringOrEmpty(row.RootPath)))
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		rows = append(rows, row)
		indexByKind[kind] = len(rows) - 1
	}

	return rows
}

type webConfigMeta struct {
	webRoot    *string
	domain     *string
	plugins    []PluginInfo
	desc       *string
	version    *string
	configPath *string
}

func inspectWebConfig(kind, path string) webConfigMeta {
	if strings.TrimSpace(path) == "" {
		return webConfigMeta{}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return webConfigMeta{configPath: nullableString(path)}
	}
	content := string(data)
	meta := webConfigMeta{configPath: nullableString(path)}
	switch kind {
	case "nginx":
		webRoot, domain, plugins := parseNginxConfig(content)
		meta.webRoot = nullableString(webRoot)
		meta.domain = nullableString(domain)
		meta.plugins = plugins
		meta.desc = strPtr("Nginx configuration")
	case "apache":
		webRoot, domain, plugins := parseApacheConfig(content)
		meta.webRoot = nullableString(webRoot)
		meta.domain = nullableString(domain)
		meta.plugins = plugins
		meta.desc = strPtr("Apache configuration")
	case "tomcat":
		webRoot, domain := parseTomcatConfig(content)
		meta.webRoot = nullableString(webRoot)
		meta.domain = nullableString(domain)
		meta.plugins = []PluginInfo{}
		meta.desc = strPtr("Tomcat configuration")
		if v := detectVersionFromText(content); v != nil {
			meta.version = v
		}
	}
	return meta
}

func mergeWebAppProcessMeta(row *WebApplicationInfo, proc processscan.ProcessInfo, cfgPath string, meta webConfigMeta) {
	row.IsRunning = boolPtr(true)
	if row.RootPath == nil {
		if meta.configPath != nil {
			row.RootPath = meta.configPath
		} else if cfgPath != "" {
			row.RootPath = nullableString(cfgPath)
		}
	}
	if row.WebRoot == nil && meta.webRoot != nil {
		row.WebRoot = meta.webRoot
	}
	if row.DomainName == nil && meta.domain != nil {
		row.DomainName = meta.domain
	}
	if len(row.Plugins) == 0 && len(meta.plugins) > 0 {
		row.Plugins = append([]PluginInfo(nil), meta.plugins...)
	}
	if row.Description == nil && meta.desc != nil {
		row.Description = meta.desc
	}
	if row.Version == nil {
		if meta.version != nil {
			row.Version = meta.version
		} else if proc.Version != nil {
			row.Version = nullableString(*proc.Version)
		}
	}
	if row.RootPath == nil && proc.Path != nil {
		row.RootPath = nullableString(*proc.Path)
	}
}

func normalizeWebKind(serverName, appName *string) string {
	for _, raw := range []string{stringOrEmpty(serverName), stringOrEmpty(appName)} {
		v := strings.ToLower(strings.TrimSpace(raw))
		switch {
		case strings.Contains(v, "nginx"):
			return "nginx"
		case strings.Contains(v, "apache"), strings.Contains(v, "httpd"):
			return "apache"
		case strings.Contains(v, "tomcat"), strings.Contains(v, "catalina"):
			return "tomcat"
		case strings.Contains(v, "iis"), strings.Contains(v, "w3wp"):
			return "iis"
		}
	}
	return ""
}

func detectWebProcessKindAndConfig(proc processscan.ProcessInfo) (kind, cfgPath string) {
	kind = detectWebProcessKind(proc)
	if kind == "" {
		return "", ""
	}
	cfgPath = extractConfigPathFromArgs(kind, stringOrEmpty(proc.StartArgs))
	if cfgPath == "" {
		cfgPath = extractConfigPathFromArgs(kind, stringOrEmpty(proc.Path))
	}
	return kind, cfgPath
}

func detectWebProcessKind(proc processscan.ProcessInfo) string {
	name := strings.ToLower(strings.TrimSpace(stringOrEmpty(proc.Name)))
	path := strings.ToLower(strings.TrimSpace(stringOrEmpty(proc.Path)))

	identityTokens := []string{name, path}
	for _, token := range identityTokens {
		if token == "" {
			continue
		}
		base := strings.ToLower(strings.TrimSpace(filepath.Base(token)))
		switch {
		case strings.Contains(token, "nginx") || strings.Contains(base, "nginx"):
			return "nginx"
		case strings.Contains(token, "httpd") || strings.Contains(base, "httpd") ||
			strings.Contains(token, "apache") || strings.Contains(base, "apache"):
			return "apache"
		case strings.Contains(token, "tomcat") || strings.Contains(base, "tomcat") ||
			strings.Contains(token, "catalina") || strings.Contains(base, "catalina"):
			return "tomcat"
		case strings.Contains(token, "w3wp") || strings.Contains(base, "w3wp") ||
			strings.Contains(token, "iis") || strings.Contains(base, "iis"):
			return "iis"
		}
	}

	// Only treat Java processes as Tomcat when canonical Catalina markers exist.
	if strings.Contains(name, "java") || strings.Contains(path, "java") {
		args := strings.ToLower(strings.TrimSpace(stringOrEmpty(proc.StartArgs)))
		if strings.Contains(args, "org.apache.catalina.startup.bootstrap") ||
			strings.Contains(args, "catalina.base") ||
			strings.Contains(args, "catalina.home") {
			return "tomcat"
		}
	}

	return ""
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

func normalizeConfigPath(path string, exePath *string) string {
	trimmed := strings.TrimSpace(strings.Trim(path, `"'`))
	if trimmed == "" {
		return ""
	}
	if filepath.IsAbs(trimmed) {
		return resolveSymlinkPath(trimmed)
	}
	if exePath == nil || strings.TrimSpace(*exePath) == "" {
		return resolveSymlinkPath(trimmed)
	}
	return resolveSymlinkPath(filepath.Join(filepath.Dir(strings.TrimSpace(*exePath)), trimmed))
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
