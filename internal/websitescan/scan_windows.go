//go:build windows

package websitescan

import (
	"context"
	"os"
	"path/filepath"
)

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

func collectWebSites(ctx context.Context) ([]WebSiteInfo, error) {
	rows := make([]WebSiteInfo, 0, 8)

	for _, path := range windowsNginxConfigPaths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resolvedPath, merged, err := loadWebSiteConfigWithIncludes(path, windowsReadFile)
		if err != nil {
			continue
		}
		webRoot, domains, port, proto, _, deny, sec := parseNginx(merged)
		rootDir, rootObj := windowsRootVirtualDir(webRoot)
		rows = append(rows, WebSiteInfo{
			Type:            strPtr("nginx"),
			Port:            port,
			Proto:           nullableString(proto),
			Deny:            nullableString(deny),
			SecurityEnabled: boolPtr(sec),
			Domains:         domains,
			VirtualDir:      rootDir,
			Root:            rootObj,
			Path:            nullableString(webRoot),
			ConfigName:      nullableString(filepath.Base(resolvedPath)),
		})
	}

	for _, path := range windowsApacheConfigPaths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resolvedPath, merged, err := loadWebSiteConfigWithIncludes(path, windowsReadFile)
		if err != nil {
			continue
		}
		webRoot, domains, port, proto := parseApache(merged)
		rootDir, rootObj := windowsRootVirtualDir(webRoot)
		rows = append(rows, WebSiteInfo{
			Type:       strPtr("apache"),
			Port:       port,
			Proto:      nullableString(proto),
			Domains:    domains,
			VirtualDir: rootDir,
			Root:       rootObj,
			Path:       nullableString(webRoot),
			ConfigName: nullableString(filepath.Base(resolvedPath)),
		})
	}

	for _, path := range windowsTomcatConfigPaths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resolvedPath, merged, err := loadWebSiteConfigWithIncludes(path, windowsReadFile)
		if err != nil {
			continue
		}
		webRoot, domains, port, proto := parseTomcat(merged)
		rootDir, rootObj := windowsRootVirtualDir(webRoot)
		rows = append(rows, WebSiteInfo{
			Type:       strPtr("tomcat"),
			Port:       port,
			Proto:      nullableString(proto),
			Domains:    domains,
			VirtualDir: rootDir,
			Root:       rootObj,
			Path:       nullableString(webRoot),
			DeployPath: nullableString(filepath.Dir(webRoot)),
			ConfigName: nullableString(filepath.Base(resolvedPath)),
		})
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	applicationHostPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "inetsrv", "config", "applicationHost.config")
	if data, err := windowsReadFile(applicationHostPath); err == nil {
		rows = append(rows, parseIISApplicationHost(data)...)
	}

	return rows, nil
}

func windowsRootVirtualDir(webRoot string) ([]VirtualDirInfo, *VirtualDirInfo) {
	rootPath := nullableString(webRoot)
	if rootPath == nil {
		return []VirtualDirInfo{}, nil
	}
	item := VirtualDirInfo{
		Path:         strPtr("/"),
		PhysicalPath: rootPath,
		Root:         boolPtr(true),
		ACLs:         []ACLInfo{},
	}
	return []VirtualDirInfo{item}, &item
}
