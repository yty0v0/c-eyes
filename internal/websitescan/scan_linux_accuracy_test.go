//go:build linux

package websitescan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCollectWebSitesLinuxAccuracyWithFixtures(t *testing.T) {
	dir := t.TempDir()
	nginxPath := filepath.Join(dir, "nginx.conf")
	apachePath := filepath.Join(dir, "httpd.conf")
	tomcatPath := filepath.Join(dir, "server.xml")

	if err := os.WriteFile(nginxPath, []byte(`
server {
  server_name app.example.com;
  root /srv/www/app;
  listen 443 ssl;
  deny all;
  modsecurity on;
}
`), 0o644); err != nil {
		t.Fatalf("write nginx fixture: %v", err)
	}
	if err := os.WriteFile(apachePath, []byte(`
ServerName intranet.example.com
DocumentRoot "/var/www/intranet"
Listen 8080
`), 0o644); err != nil {
		t.Fatalf("write apache fixture: %v", err)
	}
	if err := os.WriteFile(tomcatPath, []byte(`<Server><Service><Connector port="8443" protocol="HTTP/1.1"/><Host name="tomcat.example.com" appBase="/opt/tomcat/webapps"/></Service></Server>`), 0o644); err != nil {
		t.Fatalf("write tomcat fixture: %v", err)
	}

	origNginx := linuxNginxConfigPaths
	origApache := linuxApacheConfigPaths
	origTomcat := linuxTomcatConfigPaths
	origRead := linuxReadFile
	t.Cleanup(func() {
		linuxNginxConfigPaths = origNginx
		linuxApacheConfigPaths = origApache
		linuxTomcatConfigPaths = origTomcat
		linuxReadFile = origRead
	})
	linuxNginxConfigPaths = []string{nginxPath}
	linuxApacheConfigPaths = []string{apachePath}
	linuxTomcatConfigPaths = []string{tomcatPath}
	linuxReadFile = os.ReadFile

	rows, err := collectWebSites(context.Background())
	if err != nil {
		t.Fatalf("collect web sites: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(rows))
	}
}
