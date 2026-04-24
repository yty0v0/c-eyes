//go:build windows

package webapplicationscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCollectWebApplicationsWindowsAccuracyWithFixtures(t *testing.T) {
	dir := t.TempDir()
	nginxPath := filepath.Join(dir, "nginx.conf")
	apachePath := filepath.Join(dir, "httpd.conf")
	tomcatPath := filepath.Join(dir, "server.xml")

	if err := os.WriteFile(nginxPath, []byte(`
server {
  server_name win.example.com;
  root C:/inetpub/wwwroot;
}
load_module modules/ngx_http_image_filter_module.so;
`), 0o644); err != nil {
		t.Fatalf("write nginx fixture: %v", err)
	}
	if err := os.WriteFile(apachePath, []byte(`
ServerName intranet.win.local
DocumentRoot "D:/www/intranet"
LoadModule rewrite_module modules/mod_rewrite.so
`), 0o644); err != nil {
		t.Fatalf("write apache fixture: %v", err)
	}
	if err := os.WriteFile(tomcatPath, []byte(`<Server><Host name="tomcat.win.local" appBase="E:/tomcat/webapps"/></Server>`), 0o644); err != nil {
		t.Fatalf("write tomcat fixture: %v", err)
	}

	sysRoot := filepath.Join(dir, "windows")
	iisPath := filepath.Join(sysRoot, "System32", "inetsrv", "config")
	if err := os.MkdirAll(iisPath, 0o755); err != nil {
		t.Fatalf("mkdir iis path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(iisPath, "applicationHost.config"), []byte(`
<configuration>
  <system.applicationHost>
    <sites>
      <site name="Default Web Site">
        <application path="/">
          <virtualDirectory path="/" physicalPath="C:\inetpub\wwwroot" />
        </application>
      </site>
    </sites>
  </system.applicationHost>
</configuration>
`), 0o644); err != nil {
		t.Fatalf("write iis fixture: %v", err)
	}

	origSystemRoot, hadSystemRoot := os.LookupEnv("SystemRoot")
	origNginx := windowsNginxConfigPaths
	origApache := windowsApacheConfigPaths
	origTomcat := windowsTomcatConfigPaths
	origRead := windowsReadFile
	origServices := windowsListServices
	t.Cleanup(func() {
		windowsNginxConfigPaths = origNginx
		windowsApacheConfigPaths = origApache
		windowsTomcatConfigPaths = origTomcat
		windowsReadFile = origRead
		windowsListServices = origServices
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
	windowsListServices = func() []windowsServiceInfo {
		return []windowsServiceInfo{
			{Name: "NginxSvc", ImagePath: `"C:\nginx\nginx-1.25.4\nginx.exe"`},
		}
	}

	rows, err := collectWebApplications(context.Background())
	if err != nil {
		t.Fatalf("collect web applications: %v", err)
	}
	if len(rows) < 4 {
		t.Fatalf("expected at least 4 rows, got %d", len(rows))
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
	if nginx.DomainName == nil || *nginx.DomainName != "win.example.com" {
		t.Fatalf("unexpected nginx domain: %+v", nginx.DomainName)
	}
	if len(nginx.Plugins) == 0 {
		t.Fatalf("expected nginx plugins")
	}

	apache, ok := index["apache"]
	if !ok {
		t.Fatalf("missing apache row")
	}
	if apache.WebRoot == nil || *apache.WebRoot != "D:/www/intranet" {
		t.Fatalf("unexpected apache webRoot: %+v", apache.WebRoot)
	}

	tomcat, ok := index["tomcat"]
	if !ok {
		t.Fatalf("missing tomcat row")
	}
	if tomcat.WebRoot == nil || *tomcat.WebRoot != "E:/tomcat/webapps" {
		t.Fatalf("unexpected tomcat webRoot: %+v", tomcat.WebRoot)
	}

	iis, ok := index["iis"]
	if !ok {
		t.Fatalf("missing iis row")
	}
	if iis.WebRoot == nil || *iis.WebRoot != `C:\inetpub\wwwroot` {
		t.Fatalf("unexpected iis webRoot: %+v", iis.WebRoot)
	}
}
