//go:build windows

package webapplicationscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type windowsServiceInfo struct {
	Name      string
	ImagePath string
}

var windowsNginxConfigPaths = []string{
	`C:\nginx\conf\nginx.conf`,
	`C:\Program Files\nginx\conf\nginx.conf`,
}
var windowsApacheConfigPaths = []string{
	`C:\Apache24\conf\httpd.conf`,
	`C:\Program Files\Apache Group\Apache2\conf\httpd.conf`,
}
var windowsTomcatConfigPaths = []string{
	`C:\Program Files\Apache Software Foundation\Tomcat 9.0\conf\server.xml`,
	`C:\Tomcat\conf\server.xml`,
}
var windowsReadFile = os.ReadFile
var windowsListServices = listWindowsServices

func collectWebApplications(ctx context.Context) ([]WebApplicationInfo, error) {
	rows := make([]WebApplicationInfo, 0, 8)
	seen := map[string]struct{}{}

	appendRow := func(row WebApplicationInfo) {
		key := strings.ToLower(strings.TrimSpace(stringOrEmpty(row.ServerName)) + "|" + strings.TrimSpace(stringOrEmpty(row.RootPath)))
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		rows = append(rows, row)
	}

	for _, path := range windowsNginxConfigPaths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resolvedPath, merged, err := loadConfigWithIncludes(path, windowsReadFile)
		if err != nil {
			continue
		}
		webRoot, domain, plugins := parseNginxConfig(merged)
		row := WebApplicationInfo{
			AppName:     strPtr("nginx"),
			ServerName:  strPtr("nginx"),
			RootPath:    strPtr(resolvedPath),
			WebRoot:     nullableString(webRoot),
			DomainName:  nullableString(domain),
			Description: strPtr("Nginx configuration"),
			Plugins:     plugins,
		}
		appendRow(row)
	}

	for _, path := range windowsApacheConfigPaths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resolvedPath, merged, err := loadConfigWithIncludes(path, windowsReadFile)
		if err != nil {
			continue
		}
		webRoot, domain, plugins := parseApacheConfig(merged)
		row := WebApplicationInfo{
			AppName:     strPtr("apache"),
			ServerName:  strPtr("apache"),
			RootPath:    strPtr(resolvedPath),
			WebRoot:     nullableString(webRoot),
			DomainName:  nullableString(domain),
			Description: strPtr("Apache configuration"),
			Plugins:     plugins,
		}
		appendRow(row)
	}

	for _, path := range windowsTomcatConfigPaths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resolvedPath, merged, err := loadConfigWithIncludes(path, windowsReadFile)
		if err != nil {
			continue
		}
		webRoot, domain := parseTomcatConfig(merged)
		row := WebApplicationInfo{
			AppName:     strPtr("tomcat"),
			ServerName:  strPtr("tomcat"),
			RootPath:    strPtr(resolvedPath),
			WebRoot:     nullableString(webRoot),
			DomainName:  nullableString(domain),
			Description: strPtr("Tomcat configuration"),
			Plugins:     []PluginInfo{},
		}
		appendRow(row)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	applicationHostPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "inetsrv", "config", "applicationHost.config")
	if data, err := windowsReadFile(applicationHostPath); err == nil {
		for _, row := range parseIISApplicationHost(data) {
			appendRow(row)
		}
	}

	for _, svc := range windowsListServices() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		parsed := parseWindowsCommandLine(svc.ImagePath)
		if len(parsed) == 0 {
			continue
		}
		serverName := detectWindowsServerName(svc.Name, parsed[0])
		if serverName == "" {
			continue
		}
		if !hasServerName(rows, serverName) {
			rows = append(rows, WebApplicationInfo{
				AppName:     strPtr(serverName),
				ServerName:  strPtr(serverName),
				RootPath:    nullableString(parsed[0]),
				Version:     detectVersionFromText(svc.ImagePath),
				Description: strPtr("Detected from Windows service"),
				Plugins:     []PluginInfo{},
			})
		}
	}

	return rows, nil
}

func listWindowsServices() []windowsServiceInfo {
	services, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer services.Close()

	names, _ := services.ReadSubKeyNames(-1)
	out := make([]windowsServiceInfo, 0, len(names))
	for _, name := range names {
		svc, err := registry.OpenKey(services, name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		imagePath, _, _ := svc.GetStringValue("ImagePath")
		svc.Close()
		out = append(out, windowsServiceInfo{Name: name, ImagePath: imagePath})
	}
	return out
}

func parseWindowsCommandLine(command string) []string {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return nil
	}
	args, err := windows.DecomposeCommandLine(trimmed)
	if err == nil && len(args) > 0 {
		return args
	}
	return strings.Fields(trimmed)
}

func detectWindowsServerName(serviceName, executable string) string {
	target := strings.ToLower(strings.TrimSpace(serviceName + " " + executable))
	base := strings.ToLower(filepath.Base(executable))
	switch {
	case strings.Contains(target, "nginx") || base == "nginx.exe":
		return "nginx"
	case strings.Contains(target, "apache") || base == "httpd.exe":
		return "apache"
	case strings.Contains(target, "tomcat") || base == "tomcat9.exe" || base == "tomcat10.exe":
		return "tomcat"
	case strings.Contains(target, "w3svc") || strings.Contains(target, "iis"):
		return "iis"
	default:
		return ""
	}
}

func hasServerName(rows []WebApplicationInfo, server string) bool {
	for _, row := range rows {
		if row.ServerName != nil && strings.EqualFold(strings.TrimSpace(*row.ServerName), server) {
			return true
		}
	}
	return false
}
