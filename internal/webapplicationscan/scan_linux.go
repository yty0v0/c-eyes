//go:build linux

package webapplicationscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

var linuxNginxConfigPaths = []string{"/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf"}
var linuxApacheConfigPaths = []string{"/etc/httpd/conf/httpd.conf", "/etc/apache2/apache2.conf"}
var linuxTomcatConfigPaths = []string{
	"/etc/tomcat/server.xml",
	"/etc/tomcat9/server.xml",
	"/usr/share/tomcat/conf/server.xml",
	"/opt/tomcat/conf/server.xml",
}
var linuxReadFile = os.ReadFile

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

	for _, path := range linuxNginxConfigPaths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resolvedPath, merged, err := loadConfigWithIncludes(path, linuxReadFile)
		if err != nil {
			continue
		}
		webRoot, domain, plugins := parseNginxConfig(merged)
		row := WebApplicationInfo{
			AppName:     strPtr("nginx"),
			ServerName:  strPtr("nginx"),
			RootPath:    strPtr(resolvedPath),
			WebRoot:     pickString(webRoot, "/usr/share/nginx/html"),
			DomainName:  nullableString(domain),
			Description: strPtr("Nginx configuration"),
			Plugins:     plugins,
		}
		appendRow(row)
	}

	for _, path := range linuxApacheConfigPaths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resolvedPath, merged, err := loadConfigWithIncludes(path, linuxReadFile)
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

	for _, path := range linuxTomcatConfigPaths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resolvedPath, merged, err := loadConfigWithIncludes(path, linuxReadFile)
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
		if version := detectTomcatVersion(path); version != nil {
			row.Version = version
		}
		appendRow(row)
	}

	return rows, nil
}

func detectTomcatVersion(configPath string) *string {
	base := filepath.Dir(filepath.Dir(configPath))
	for _, rel := range []string{"RELEASE-NOTES", "RUNNING.txt"} {
		path := filepath.Join(base, rel)
		data, err := linuxReadFile(path)
		if err != nil {
			continue
		}
		if version := detectVersionFromText(string(data)); version != nil {
			return version
		}
	}
	return nil
}

func pickString(primary, fallback string) *string {
	if out := nullableString(primary); out != nil {
		return out
	}
	return nullableString(fallback)
}
