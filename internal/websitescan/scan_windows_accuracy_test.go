//go:build windows

package websitescan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCollectWebSitesWindowsAccuracyWithFixtures(t *testing.T) {
	dir := t.TempDir()
	nginxPath := filepath.Join(dir, "nginx.conf")
	apachePath := filepath.Join(dir, "httpd.conf")
	tomcatPath := filepath.Join(dir, "server.xml")

	if err := os.WriteFile(nginxPath, []byte(`
server {
  server_name win.example.com;
  root C:/inetpub/wwwroot;
  listen 80;
}
`), 0o644); err != nil {
		t.Fatalf("write nginx fixture: %v", err)
	}
	if err := os.WriteFile(apachePath, []byte(`
ServerName intranet.win.local
DocumentRoot "D:/www/intranet"
Listen 8080
`), 0o644); err != nil {
		t.Fatalf("write apache fixture: %v", err)
	}
	if err := os.WriteFile(tomcatPath, []byte(`<Server><Service><Connector port="8080" protocol="HTTP/1.1"/><Host name="tomcat.win.local" appBase="E:/tomcat/webapps"/></Service></Server>`), 0o644); err != nil {
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
      <site name="Default Web Site" serverAutoStart="true">
        <bindings>
          <binding protocol="http" bindingInformation="*:80:example.local"/>
        </bindings>
        <application path="/" applicationPool="DefaultAppPool">
          <virtualDirectory path="/" physicalPath="C:\inetpub\wwwroot" />
        </application>
      </site>
    </sites>
    <applicationPools>
      <add name="DefaultAppPool">
        <processModel identityType="LocalSystem" userName="SYSTEM" />
      </add>
    </applicationPools>
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
	if len(rows) < 4 {
		t.Fatalf("expected at least 4 rows, got %d", len(rows))
	}
}
