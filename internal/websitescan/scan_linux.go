//go:build linux

package websitescan

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
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
var linuxStat = os.Stat

func collectWebSites(ctx context.Context) ([]WebSiteInfo, error) {
	rows := make([]WebSiteInfo, 0, 8)

	for _, path := range linuxNginxConfigPaths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resolvedPath, merged, err := loadWebSiteConfigWithIncludes(path, linuxReadFile)
		if err != nil {
			continue
		}
		webRoot, domains, port, proto, allow, deny, sec := parseNginx(merged)
		rootDir, rootObj := linuxRootVirtualDir(webRoot)
		rows = append(rows, WebSiteInfo{
			Type:            strPtr("nginx"),
			Port:            port,
			Proto:           nullableString(proto),
			Allow:           nullableString(allow),
			Deny:            nullableString(deny),
			SecurityEnabled: boolPtr(sec),
			Domains:         domains,
			VirtualDir:      rootDir,
			Root:            rootObj,
			Path:            nullableString(webRoot),
			ConfigName:      nullableString(filepath.Base(resolvedPath)),
		})
	}

	for _, path := range linuxApacheConfigPaths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resolvedPath, merged, err := loadWebSiteConfigWithIncludes(path, linuxReadFile)
		if err != nil {
			continue
		}
		webRoot, domains, port, proto := parseApache(merged)
		rootDir, rootObj := linuxRootVirtualDir(webRoot)
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

	for _, path := range linuxTomcatConfigPaths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resolvedPath, merged, err := loadWebSiteConfigWithIncludes(path, linuxReadFile)
		if err != nil {
			continue
		}
		webRoot, domains, port, proto := parseTomcat(merged)
		rootDir, rootObj := linuxRootVirtualDir(webRoot)
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

	return rows, nil
}

func linuxRootVirtualDir(webRoot string) ([]VirtualDirInfo, *VirtualDirInfo) {
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
	if stat, err := linuxStat(*rootPath); err == nil {
		if mode := stat.Mode(); mode != 0 {
			item.Permission = strPtr(mode.Perm().String())
		}
		if sys, ok := stat.Sys().(*syscall.Stat_t); ok {
			item.Owner = strPtr(strconvFormatUint(sys.Uid))
			item.Group = int64Ptr(int64(sys.Gid))
		}
	}
	return []VirtualDirInfo{item}, &item
}

func strconvFormatUint(v uint32) string {
	return strconv.FormatUint(uint64(v), 10)
}
