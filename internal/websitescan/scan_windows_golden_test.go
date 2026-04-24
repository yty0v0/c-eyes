//go:build windows

package websitescan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCollectWebSitesWindowsGolden(t *testing.T) {
	fixtureDir := filepath.FromSlash("testdata/windows")
	nginxSrc := filepath.Join(fixtureDir, "nginx.conf")
	apacheSrc := filepath.Join(fixtureDir, "httpd.conf")
	tomcatSrc := filepath.Join(fixtureDir, "server.xml")
	iisSrc := filepath.Join(fixtureDir, "applicationHost.config")

	nginxData, err := os.ReadFile(nginxSrc)
	if err != nil {
		t.Fatalf("read nginx fixture: %v", err)
	}
	apacheData, err := os.ReadFile(apacheSrc)
	if err != nil {
		t.Fatalf("read apache fixture: %v", err)
	}
	tomcatData, err := os.ReadFile(tomcatSrc)
	if err != nil {
		t.Fatalf("read tomcat fixture: %v", err)
	}
	iisData, err := os.ReadFile(iisSrc)
	if err != nil {
		t.Fatalf("read iis fixture: %v", err)
	}

	dir := t.TempDir()
	nginxPath := filepath.Join(dir, "nginx.conf")
	apachePath := filepath.Join(dir, "httpd.conf")
	tomcatPath := filepath.Join(dir, "server.xml")
	if err := os.WriteFile(nginxPath, nginxData, 0o644); err != nil {
		t.Fatalf("write nginx fixture: %v", err)
	}
	if err := os.WriteFile(apachePath, apacheData, 0o644); err != nil {
		t.Fatalf("write apache fixture: %v", err)
	}
	if err := os.WriteFile(tomcatPath, tomcatData, 0o644); err != nil {
		t.Fatalf("write tomcat fixture: %v", err)
	}

	sysRoot := filepath.Join(dir, "windows")
	iisPath := filepath.Join(sysRoot, "System32", "inetsrv", "config")
	if err := os.MkdirAll(iisPath, 0o755); err != nil {
		t.Fatalf("mkdir iis path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(iisPath, "applicationHost.config"), iisData, 0o644); err != nil {
		t.Fatalf("write iis fixture: %v", err)
	}

	origSystemRoot, hadSystemRoot := os.LookupEnv("SystemRoot")
	origNginx := windowsNginxConfigPaths
	origApache := windowsApacheConfigPaths
	origTomcat := windowsTomcatConfigPaths
	origRead := windowsReadFile
	t.Cleanup(func() {
		windowsNginxConfigPaths = origNginx
		windowsApacheConfigPaths = origApache
		windowsTomcatConfigPaths = origTomcat
		windowsReadFile = origRead
		if hadSystemRoot {
			_ = os.Setenv("SystemRoot", origSystemRoot)
		} else {
			_ = os.Unsetenv("SystemRoot")
		}
	})
	if err := os.Setenv("SystemRoot", sysRoot); err != nil {
		t.Fatalf("set SystemRoot: %v", err)
	}
	windowsNginxConfigPaths = []string{nginxPath}
	windowsApacheConfigPaths = []string{apachePath}
	windowsTomcatConfigPaths = []string{tomcatPath}
	windowsReadFile = os.ReadFile

	rows, err := collectWebSites(context.Background())
	if err != nil {
		t.Fatalf("collect web sites: %v", err)
	}
	for i := range rows {
		normalizeDefaults(&rows[i])
	}
	assertGoldenJSON(t, filepath.Join(fixtureDir, "expected.json"), rows)
}
