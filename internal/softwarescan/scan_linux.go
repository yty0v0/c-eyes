//go:build linux

package softwarescan

import (
	"context"
	"os"
	"strings"
)

var linuxReadFile = os.ReadFile
var linuxStat = os.Stat

var linuxStaticCandidates = []struct {
	Name        string
	BinPaths    []string
	ConfigPaths []string
	Packages    []string
}{
	{
		Name:        "nginx",
		BinPaths:    []string{"/usr/sbin/nginx", "/usr/local/nginx/sbin/nginx"},
		ConfigPaths: []string{"/etc/nginx/nginx.conf", "/usr/local/nginx/conf/nginx.conf"},
		Packages:    []string{"nginx"},
	},
	{
		Name:        "apache",
		BinPaths:    []string{"/usr/sbin/httpd", "/usr/sbin/apache2"},
		ConfigPaths: []string{"/etc/httpd/conf/httpd.conf", "/etc/apache2/apache2.conf"},
		Packages:    []string{"apache2", "httpd"},
	},
	{
		Name:        "tomcat",
		BinPaths:    []string{"/usr/share/tomcat/bin/catalina.sh", "/opt/tomcat/bin/catalina.sh"},
		ConfigPaths: []string{"/etc/tomcat/server.xml", "/etc/tomcat9/server.xml", "/usr/share/tomcat/conf/server.xml", "/opt/tomcat/conf/server.xml"},
		Packages:    []string{"tomcat", "tomcat9", "tomcat10"},
	},
	{
		Name:        "mysql",
		BinPaths:    []string{"/usr/sbin/mysqld", "/usr/bin/mysqld"},
		ConfigPaths: []string{"/etc/my.cnf", "/etc/mysql/my.cnf"},
		Packages:    []string{"mysql-server", "mariadb-server"},
	},
	{
		Name:        "redis",
		BinPaths:    []string{"/usr/bin/redis-server", "/usr/local/bin/redis-server"},
		ConfigPaths: []string{"/etc/redis/redis.conf"},
		Packages:    []string{"redis-server", "redis"},
	},
	{
		Name:        "postgresql",
		BinPaths:    []string{"/usr/lib/postgresql/15/bin/postgres", "/usr/lib/postgresql/14/bin/postgres", "/usr/bin/postgres"},
		ConfigPaths: []string{"/etc/postgresql/15/main/postgresql.conf", "/etc/postgresql/14/main/postgresql.conf", "/var/lib/pgsql/data/postgresql.conf"},
		Packages:    []string{"postgresql"},
	},
}

func collectSoftware(ctx context.Context) ([]SoftwareInfo, error) {
	rows, err := collectSoftwareFromProcesses(ctx)
	if err != nil {
		return nil, err
	}

	packageVersions := readLinuxPackageVersions()
	for _, candidate := range linuxStaticCandidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row := SoftwareInfo{
			Name:      nullableString(candidate.Name),
			Processes: []SoftwareProcess{},
		}
		row.BinPath = firstExistingPath(candidate.BinPaths)
		row.ConfigPath = firstExistingPath(candidate.ConfigPaths)
		if row.BinPath == nil && row.ConfigPath == nil {
			continue
		}
		if version := findPackageVersion(packageVersions, candidate.Packages); version != "" {
			row.Version = nullableString(version)
		}
		rows = append(rows, row)
	}

	return rows, nil
}

func firstExistingPath(paths []string) *string {
	for _, path := range paths {
		trimmed := strings.TrimSpace(path)
		if trimmed == "" {
			continue
		}
		if _, err := linuxStat(trimmed); err == nil {
			return normalizePath(trimmed)
		}
	}
	return nil
}

func readLinuxPackageVersions() map[string]string {
	data, err := linuxReadFile("/var/lib/dpkg/status")
	if err != nil {
		return map[string]string{}
	}

	out := map[string]string{}
	var pkg, version string
	lines := strings.Split(string(data), "\n")
	flush := func() {
		if strings.TrimSpace(pkg) == "" || strings.TrimSpace(version) == "" {
			pkg = ""
			version = ""
			return
		}
		out[strings.ToLower(strings.TrimSpace(pkg))] = strings.TrimSpace(version)
		pkg = ""
		version = ""
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "Package:") {
			pkg = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
			continue
		}
		if strings.HasPrefix(line, "Version:") {
			version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		}
	}
	flush()
	return out
}

func findPackageVersion(versions map[string]string, candidates []string) string {
	for _, candidate := range candidates {
		key := strings.ToLower(strings.TrimSpace(candidate))
		if key == "" {
			continue
		}
		if version, ok := versions[key]; ok {
			return version
		}
	}
	return ""
}
