//go:build linux

package webapplicationscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCollectWebApplicationsLinuxAccuracyWithFixtures(t *testing.T) {
	dir := t.TempDir()

	nginxPath := filepath.Join(dir, "nginx.conf")
	apachePath := filepath.Join(dir, "httpd.conf")
	tomcatConfDir := filepath.Join(dir, "tomcat", "conf")
	if err := os.MkdirAll(tomcatConfDir, 0o755); err != nil {
		t.Fatalf("mkdir tomcat conf: %v", err)
	}
	tomcatPath := filepath.Join(tomcatConfDir, "server.xml")
	releaseNotes := filepath.Join(dir, "tomcat", "RELEASE-NOTES")

	if err := os.WriteFile(nginxPath, []byte(`
server {
  server_name app.example.com;
  root /srv/www/app;
}
load_module modules/ngx_http_geoip_module.so;
`), 0o644); err != nil {
		t.Fatalf("write nginx fixture: %v", err)
	}
	if err := os.WriteFile(apachePath, []byte(`
ServerName intranet.example.com
DocumentRoot "/var/www/intranet"
LoadModule rewrite_module modules/mod_rewrite.so
`), 0o644); err != nil {
		t.Fatalf("write apache fixture: %v", err)
	}
	if err := os.WriteFile(tomcatPath, []byte(`<Server><Host name="tomcat.example.com" appBase="/opt/tomcat/webapps"/></Server>`), 0o644); err != nil {
		t.Fatalf("write tomcat fixture: %v", err)
	}
	if err := os.WriteFile(releaseNotes, []byte("Apache Tomcat Version 9.0.80"), 0o644); err != nil {
		t.Fatalf("write release notes: %v", err)
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

	rows, err := collectWebApplications(context.Background())
	if err != nil {
		t.Fatalf("collect web applications: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(rows))
	}

	index := map[string]WebApplicationInfo{}
	for _, row := range rows {
		if row.ServerName == nil {
			continue
		}
		index[*row.ServerName] = row
	}

	nginx, ok := index["nginx"]
	if !ok {
		t.Fatalf("missing nginx row")
	}
	if nginx.WebRoot == nil || *nginx.WebRoot != "/srv/www/app" {
		t.Fatalf("unexpected nginx webRoot: %+v", nginx.WebRoot)
	}
	if nginx.DomainName == nil || *nginx.DomainName != "app.example.com" {
		t.Fatalf("unexpected nginx domain: %+v", nginx.DomainName)
	}
	if len(nginx.Plugins) != 1 {
		t.Fatalf("expected nginx plugin count 1, got %d", len(nginx.Plugins))
	}

	apache, ok := index["apache"]
	if !ok {
		t.Fatalf("missing apache row")
	}
	if apache.WebRoot == nil || *apache.WebRoot != "/var/www/intranet" {
		t.Fatalf("unexpected apache webRoot: %+v", apache.WebRoot)
	}
	if apache.DomainName == nil || *apache.DomainName != "intranet.example.com" {
		t.Fatalf("unexpected apache domain: %+v", apache.DomainName)
	}
	if len(apache.Plugins) != 1 {
		t.Fatalf("expected apache plugin count 1, got %d", len(apache.Plugins))
	}

	tomcat, ok := index["tomcat"]
	if !ok {
		t.Fatalf("missing tomcat row")
	}
	if tomcat.WebRoot == nil || *tomcat.WebRoot != "/opt/tomcat/webapps" {
		t.Fatalf("unexpected tomcat webRoot: %+v", tomcat.WebRoot)
	}
	if tomcat.DomainName == nil || *tomcat.DomainName != "tomcat.example.com" {
		t.Fatalf("unexpected tomcat domain: %+v", tomcat.DomainName)
	}
	if tomcat.Version == nil || *tomcat.Version != "9.0.80" {
		t.Fatalf("unexpected tomcat version: %+v", tomcat.Version)
	}
}
