//go:build linux

package websitescan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCollectWebSitesLinuxGolden(t *testing.T) {
	fixtureDir := filepath.FromSlash("testdata/linux")
	nginxSrc := filepath.Join(fixtureDir, "nginx.conf")
	apacheSrc := filepath.Join(fixtureDir, "httpd.conf")
	tomcatSrc := filepath.Join(fixtureDir, "server.xml")

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

	origNginx := linuxNginxConfigPaths
	origApache := linuxApacheConfigPaths
	origTomcat := linuxTomcatConfigPaths
	origRead := linuxReadFile
	origStat := linuxStat
	t.Cleanup(func() {
		linuxNginxConfigPaths = origNginx
		linuxApacheConfigPaths = origApache
		linuxTomcatConfigPaths = origTomcat
		linuxReadFile = origRead
		linuxStat = origStat
	})
	linuxNginxConfigPaths = []string{nginxPath}
	linuxApacheConfigPaths = []string{apachePath}
	linuxTomcatConfigPaths = []string{tomcatPath}
	linuxReadFile = os.ReadFile
	linuxStat = func(name string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}

	rows, err := collectWebSites(context.Background())
	if err != nil {
		t.Fatalf("collect web sites: %v", err)
	}
	for i := range rows {
		normalizeDefaults(&rows[i])
	}
	assertGoldenJSON(t, filepath.Join(fixtureDir, "expected.json"), rows)
}
