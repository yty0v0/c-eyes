package webapplicationscan

import "testing"

func TestParseLinuxNginxFixtureWithPlugins(t *testing.T) {
	fixture := `
server {
  listen 80;
  server_name example.com;
  root /var/www/html;
}
load_module modules/ngx_http_geoip_module.so;
`
	webRoot, domain, plugins := parseNginxConfig(fixture)
	if webRoot != "/var/www/html" {
		t.Fatalf("unexpected webRoot: %q", webRoot)
	}
	if domain != "example.com" {
		t.Fatalf("unexpected domain: %q", domain)
	}
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}
	if plugins[0].PluginName == nil || *plugins[0].PluginName != "ngx_http_geoip_module.so" {
		t.Fatalf("unexpected plugin name: %+v", plugins[0].PluginName)
	}
}

func TestParseWindowsIISFixture(t *testing.T) {
	fixture := []byte(`
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
</configuration>`)
	rows := parseIISApplicationHost(fixture)
	if len(rows) != 1 {
		t.Fatalf("expected 1 iis row, got %d", len(rows))
	}
	row := rows[0]
	if row.ServerName == nil || *row.ServerName != "iis" {
		t.Fatalf("expected serverName iis, got %+v", row.ServerName)
	}
	if row.WebRoot == nil || *row.WebRoot != `C:\inetpub\wwwroot` {
		t.Fatalf("unexpected webRoot: %+v", row.WebRoot)
	}
}

func TestParseApacheFixtureWithLoadModules(t *testing.T) {
	fixture := `
ServerName intranet.local
DocumentRoot "/var/www/intranet"
LoadModule rewrite_module modules/mod_rewrite.so
`
	webRoot, domain, plugins := parseApacheConfig(fixture)
	if webRoot != "/var/www/intranet" {
		t.Fatalf("unexpected webRoot: %q", webRoot)
	}
	if domain != "intranet.local" {
		t.Fatalf("unexpected domain: %q", domain)
	}
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}
	if plugins[0].PluginName == nil || *plugins[0].PluginName != "rewrite_module" {
		t.Fatalf("unexpected plugin name: %+v", plugins[0].PluginName)
	}
}
